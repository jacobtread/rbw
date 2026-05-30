use anyhow::Context as _;
use tokio::{
    net::{UnixListener, UnixStream},
    time::{sleep_until, Instant},
};

use crate::agent::state::State;

mod actions;
pub mod ssh_agent;

pub(crate) mod state;

#[derive(Clone)]
pub struct Agent {
    state: State,
}

impl Agent {
    pub fn new(state: State) -> Self {
        Self { state }
    }

    async fn sleep_until_deadline(deadline: Option<Instant>) {
        match deadline {
            Some(d) => sleep_until(d).await,
            None => std::future::pending().await,
        }
    }

    async fn on_notification(&self, message: crate::notifications::Message) {
        match message {
            crate::notifications::Message::Logout => {
                log::debug!("Received Logout Message via notification channel");
                self.state.clear().await;
            }
            crate::notifications::Message::Sync => {
                log::debug!("Received Sync Message via notification channel");
                self.state.set_sync_timeout().await;

                if let Err(e) = self.sync(None).await {
                    eprintln!("failed to sync: {e:#}");
                }
            }
            crate::notifications::Message::Disconnected => {
                log::warn!("Notifications websocket disconnected");
            }
        }
    }

    async fn on_connection(&self, stream: UnixStream) {
        let mut sock = crate::sock::Sock::new(stream);

        let self_ref = self.clone();

        // TODO: Check if does it make sense to handle this in another task
        tokio::spawn(async move {
            let res = self_ref.handle_request(&mut sock).await;
            if let Err(e) = res {
                sock.send(&rbw::protocol::Response::Error {
                    error: format!("{e:#}"),
                })
                .await
                .expect("failed to send error response to client");
            }
        });
    }

    pub async fn run(self, listener: UnixListener) -> anyhow::Result<()> {
        let mut nchannel = self.state.notifications_handler().await.get_channel();

        match actions::subscribe_to_notifications(&self.state).await {
            Ok(_) => {
                log::debug!("Successfully subscribed to notifications");
            }
            Err(e) => {
                log::warn!("Failed to subscribe to notifications: {e}");
            }
        };

        loop {
            let lock_deadline = *self.state.inner.lock_deadline.lock().await;
            let sync_deadline = *self.state.inner.sync_deadline.lock().await;

            tokio::select! {
                message = nchannel.recv() => {
                    let message = message?;
                    self.on_notification(message).await;
                },
                // TODO: The client does like a hundred connections to do basic things. Maybe it
                // makes sense to create more comprehensive opcodes.
                res = listener.accept() => {
                    log::debug!("Received a connection.");

                    let res = res.context("failed to accept incoming connection")?;

                    self.on_connection(res.0).await;
                },
                _ = Self::sleep_until_deadline(lock_deadline) => {
                    self.state.clear().await;
                },
                _ = Self::sleep_until_deadline(sync_deadline) => {
                    //let state = self.state.clone();

                    self.state.set_sync_timeout().await;

                    // this could fail if we aren't logged in, but we
                    // don't care about that
                    if let Err(e) = self.sync(None).await {
                        eprintln!("failed to sync: {e:#}");
                    }

                }
            }
        }
    }

    async fn handle_request(&self, sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
        let req = match sock.recv().await? {
            Ok(msg) => msg,
            Err(error) => {
                sock.send(&rbw::protocol::Response::Error { error }).await?;
                return Ok(());
            }
        };

        let (action, environment) = req.into_parts();

        let set_timeout = match &action {
            rbw::protocol::Action::Register => {
                self.register(sock, &environment).await?;
                true
            }
            rbw::protocol::Action::Login => {
                self.login(sock, &environment).await?;
                true
            }
            rbw::protocol::Action::Unlock => {
                self.unlock(sock, &environment).await?;
                true
            }
            rbw::protocol::Action::CheckLock => {
                self.check_lock(sock).await?;
                false
            }
            rbw::protocol::Action::Lock => {
                self.lock(sock).await?;
                false
            }
            rbw::protocol::Action::Sync => {
                self.sync(Some(sock)).await?;
                false
            }
            // TODO: This alone does not do much, as it's a simple oracle open for everybody, to
            // decrypt stuff.
            rbw::protocol::Action::Decrypt {
                cipherstring,
                entry_key,
                org_id,
            } => {
                self.decrypt(
                    sock,
                    &environment,
                    cipherstring,
                    entry_key.as_deref(),
                    org_id.as_deref(),
                )
                .await?;
                true
            }
            rbw::protocol::Action::Encrypt { plaintext, org_id } => {
                self.encrypt(sock, plaintext, org_id.as_deref()).await?;
                true
            }
            rbw::protocol::Action::ClipboardStore { text } => {
                self.clipboard_store(sock, text).await?;
                true
            }
            // TODO: It's better to handle the closing more gracefully
            rbw::protocol::Action::Quit => std::process::exit(0),
            rbw::protocol::Action::Version => {
                sock.send(&rbw::protocol::Response::Version {
                    version: rbw::protocol::VERSION,
                })
                .await?;
                false
            }
        };

        self.state.set_last_environment(environment).await;

        if set_timeout {
            self.state.set_timeout().await;
        }

        Ok(())
    }
}
