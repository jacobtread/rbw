use anyhow::Context as _;
use tokio::{
    net::UnixListener,
    time::{sleep_until, Instant},
};

pub struct Agent {
    state: crate::state::State,
}

impl Agent {
    pub fn new(state: crate::state::State) -> Self {
        Self { state }
    }

    async fn sleep_until_deadline(deadline: Option<Instant>) {
        match deadline {
            Some(d) => sleep_until(d).await,
            None => std::future::pending().await,
        }
    }

    pub async fn run(self, listener: UnixListener) -> anyhow::Result<()> {
        // TODO: Notification stuff is only created after first Sync is issued.
        let mut nchannel = self.state.notifications_handler().await.get_channel().await;

        loop {
            let lock_deadline = *self.state.inner.lock_deadline.lock().await;
            let sync_deadline = *self.state.inner.sync_deadline.lock().await;

            tokio::select! {
                message = nchannel.recv() => {
                    match message {
                        Some(crate::notifications::Message::Logout) => {
                            log::debug!("Received Logout Message via notification channel");
                            self.state.clear().await;
                        },
                        Some(crate::notifications::Message::Sync) => {
                            log::debug!("Received Sync Message via notification channel");
                            self.state.set_sync_timeout().await;

                            if let Err(e) = crate::actions::sync(None, &self.state).await {
                                eprintln!("failed to sync: {e:#}");
                            }
                        },
                        None => {
                            log::debug!("Notification channel dropped. Recreating it...");
                            nchannel = self
                            .state
                            .notifications_handler()
                            .await
                            .get_channel()
                            .await;
                        },
                    }

                },
                // TODO: The client does like a hundred connections to do basic things. Maybe it
                // makes sense to create more comprehensive opcodes.
                res = listener.accept() => {

                    log::debug!("Received a connection.");

                    let res = res.context("failed to accept incoming connection")?;

                    let mut sock = crate::sock::Sock::new(res.0);

                    let state = self.state.clone();

                    // TODO: Check if does it make sense to handle this in another task
                    tokio::spawn(async move {
                        let res = handle_request(&mut sock, state.clone()).await;
                        if let Err(e) = res {
                            sock.send(&rbw::protocol::Response::Error {
                                error: format!("{e:#}"),
                            })
                            .await
                            .expect("failed to send error response to client");
                        }
                    });
                },
                _ = Self::sleep_until_deadline(lock_deadline) => {
                    self.state.clear().await;
                },
                _ = Self::sleep_until_deadline(sync_deadline) => {
                    //let state = self.state.clone();

                    self.state.set_sync_timeout().await;

                    //tokio::spawn(async move {
                        // this could fail if we aren't logged in, but we
                        // don't care about that
                        if let Err(e) = crate::actions::sync(None, &self.state).await {
                            eprintln!("failed to sync: {e:#}");
                        }
                    //});

                }
            }
        }
    }
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
) -> anyhow::Result<()> {
    let req = sock.recv().await?;
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&rbw::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let (action, environment) = req.into_parts();
    let set_timeout = match &action {
        rbw::protocol::Action::Register => {
            crate::actions::register(sock, state.clone(), &environment).await?;
            true
        }
        rbw::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), &environment).await?;
            true
        }
        rbw::protocol::Action::Unlock => {
            crate::actions::unlock(sock, &state, &environment).await?;
            true
        }
        rbw::protocol::Action::CheckLock => {
            crate::actions::check_lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
            false
        }
        rbw::protocol::Action::Sync => {
            crate::actions::sync(Some(sock), &state).await?;
            false
        }
        // TODO: This alone does not do much, as it's a simple oracle open for everybody, to
        // decrypt stuff.
        rbw::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
        } => {
            crate::actions::decrypt(
                sock,
                state.clone(),
                &environment,
                cipherstring,
                entry_key.as_deref(),
                org_id.as_deref(),
            )
            .await?;
            true
        }
        rbw::protocol::Action::Encrypt { plaintext, org_id } => {
            crate::actions::encrypt(sock, state.clone(), plaintext, org_id.as_deref()).await?;
            true
        }
        rbw::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(sock, state.clone(), text).await?;
            true
        }
        // TODO: It's better to handle the closing more gracefully
        rbw::protocol::Action::Quit => std::process::exit(0),
        rbw::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            false
        }
    };

    state.set_last_environment(environment).await;

    if set_timeout {
        state.set_timeout().await;
    }

    Ok(())
}
