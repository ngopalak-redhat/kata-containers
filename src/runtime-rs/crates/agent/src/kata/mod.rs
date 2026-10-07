// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

mod agent;
mod trans;

use std::{
    os::fd::{BorrowedFd, OwnedFd},
    os::unix::io::RawFd,
    sync::Arc,
};

use anyhow::{Context, Result};
use kata_types::config::Agent as AgentConfig;
use protocols::{agent_ttrpc_async as agent_ttrpc, health_ttrpc_async as health_ttrpc};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;
use tokio::sync::RwLock;
use ttrpc::asynchronous::Client;

use crate::{log_forwarder::LogForwarder, sock};

// https://github.com/firecracker-microvm/firecracker/blob/master/docs/vsock.md
#[derive(Debug, Default)]
pub struct Vsock {
    pub context_id: u64,
    pub port: u32,
}

#[cfg(test)]
mod suspend_tests {
    use super::*;
    use crate::{Agent, AgentManager};
    use std::os::fd::AsRawFd;
    use tokio::io::AsyncReadExt;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn suspension_closes_old_transport_and_blocks_waiters() {
        let agent = Arc::new(KataAgent::new(AgentConfig::default()));
        let (stream, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let fd = stream.as_raw_fd();
        {
            let mut inner = agent.inner.write().await;
            inner.client_fd = fd;
            inner.client_shutdown_fd = Some(
                unsafe { BorrowedFd::borrow_raw(fd) }
                    .try_clone_to_owned()
                    .unwrap(),
            );
            inner.client = Some(Client::new(stream.into()));
        }
        let epoch = agent.transport_epoch.load(Ordering::SeqCst);
        agent.suspend_transport().await.unwrap();
        assert!(agent.transport_changed(epoch));
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(timeout(Duration::from_millis(20), agent.wait_connected())
            .await
            .is_err());
        // A failed reconnect must keep health/WaitProcess parked.
        assert!(agent.resume_transport().await.is_err());
        assert!(*agent.suspended.borrow());
        agent.suspended.send_replace(false);
        timeout(Duration::from_secs(1), agent.wait_connected())
            .await
            .unwrap()
            .unwrap();
        // An old request must still notice a whole suspend/resume cycle.
        assert!(agent.transport_changed(epoch));
    }

    #[tokio::test]
    async fn suspended_mutating_rpc_fails_without_waiting_for_resume() {
        let agent = KataAgent::new(AgentConfig::default());
        agent.suspend_transport().await.unwrap();
        let result = timeout(
            Duration::from_secs(1),
            agent.pause_container(crate::ContainerID::new("c")),
        )
        .await
        .unwrap();
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("VM is suspended"));
    }
}

pub(crate) struct KataAgentInner {
    /// TTRPC client
    pub client: Option<Client>,

    /// Client fd
    pub client_fd: RawFd,
    // Own a duplicate so a closed/reused raw fd can never be shut down by
    // suspend_transport. The ttrpc receive task owns the original descriptor.
    client_shutdown_fd: Option<OwnedFd>,

    /// Unix domain socket address
    pub socket_address: String,

    /// Agent config
    config: AgentConfig,

    /// Log forwarder
    log_forwarder: LogForwarder,
}

impl std::fmt::Debug for KataAgentInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KataAgentInner")
            .field("client_fd", &self.client_fd)
            .field("socket_address", &self.socket_address)
            .field("config", &self.config)
            .finish()
    }
}

unsafe impl Send for KataAgent {}
unsafe impl Sync for KataAgent {}
#[derive(Debug)]
pub struct KataAgent {
    pub(crate) inner: Arc<RwLock<KataAgentInner>>,
    pub(crate) suspended: watch::Sender<bool>,
    pub(crate) transport_epoch: AtomicU64,
}

impl KataAgent {
    pub fn new(config: AgentConfig) -> Self {
        KataAgent {
            suspended: watch::channel(false).0,
            transport_epoch: AtomicU64::new(0),
            inner: Arc::new(RwLock::new(KataAgentInner {
                client: None,
                client_fd: -1,
                client_shutdown_fd: None,
                socket_address: "".to_string(),
                config,
                log_forwarder: LogForwarder::new(),
            })),
        }
    }

    pub(crate) async fn wait_connected(&self) -> Result<()> {
        let mut state = self.suspended.subscribe();
        while {
            let paused = *state.borrow_and_update();
            paused
        } {
            state
                .changed()
                .await
                .context("agent suspend channel closed")?;
        }
        Ok(())
    }

    pub(crate) fn transport_changed(&self, epoch: u64) -> bool {
        self.transport_epoch.load(Ordering::SeqCst) != epoch || *self.suspended.borrow()
    }

    pub async fn get_health_client(&self) -> Option<(health_ttrpc::HealthClient, i64, RawFd)> {
        let inner = self.inner.read().await;
        inner.client.as_ref().map(|c| {
            (
                health_ttrpc::HealthClient::new(c.clone()),
                inner.config.health_check_request_timeout_ms as i64,
                inner.client_fd,
            )
        })
    }

    pub async fn get_agent_client(&self) -> Option<(agent_ttrpc::AgentServiceClient, i64, RawFd)> {
        let inner = self.inner.read().await;
        inner.client.as_ref().map(|c| {
            (
                agent_ttrpc::AgentServiceClient::new(c.clone()),
                inner.config.request_timeout_ms as i64,
                inner.client_fd,
            )
        })
    }

    pub(crate) async fn set_socket_address(&self, address: &str) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.socket_address = address.to_string();
        Ok(())
    }

    pub(crate) async fn connect_agent_server(&self) -> Result<()> {
        let mut inner = self.inner.write().await;

        let config = sock::ConnectConfig::new(
            inner.config.dial_timeout_ms as u64,
            inner.config.reconnect_timeout_ms as u64,
        );
        let sock =
            sock::new(&inner.socket_address, inner.config.server_port).context("new sock")?;
        info!(sl!(), "try to connect agent server through {:?}", sock);
        let stream = sock.connect(&config).await.context("connect")?;
        let client_fd = stream.raw_fd();
        let shutdown_fd = unsafe { BorrowedFd::borrow_raw(client_fd) }.try_clone_to_owned()?;
        info!(
            sl!(),
            "get stream raw fd {:?} with socket address: {:?} and server_port {:?}",
            client_fd,
            &inner.socket_address,
            inner.config.server_port
        );
        let c = Client::new(stream.into_ttrpc_socket());
        inner.client = Some(c);
        inner.client_fd = client_fd;
        inner.client_shutdown_fd = Some(shutdown_fd);
        Ok(())
    }

    pub(crate) async fn start_log_forwarder(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        let config = sock::ConnectConfig::new(
            inner.config.dial_timeout_ms as u64,
            inner.config.reconnect_timeout_ms as u64,
        );
        let address = inner.socket_address.clone();
        let port = inner.config.log_port;
        inner
            .log_forwarder
            .start(&address, port, config)
            .await
            .context("start log forwarder")?;
        Ok(())
    }

    pub(crate) async fn stop_log_forwarder(&self) {
        let mut inner = self.inner.write().await;
        inner.log_forwarder.stop();
    }

    pub(crate) async fn agent_sock(&self) -> Result<String> {
        let inner = self.inner.read().await;
        Ok(format!(
            "{}:{}",
            inner.socket_address.clone(),
            inner.config.server_port
        ))
    }

    pub(crate) async fn agent_config(&self) -> AgentConfig {
        let inner = self.inner.read().await;
        inner.config.clone()
    }

    /// Disconnect from the agent gRPC server and clean up related resources.
    pub(crate) async fn disconnect(&self) -> Result<()> {
        let mut inner = self.inner.write().await;
        inner.log_forwarder.stop();

        // If there is a valid client, drop it (closes the connection).
        inner.client.take();
        inner.client_shutdown_fd.take();
        inner.client_fd = -1;

        Ok(())
    }
}
