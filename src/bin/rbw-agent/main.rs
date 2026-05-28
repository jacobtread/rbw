use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Context as _;
#[cfg(feature = "clipboard")]
use tokio::sync::Mutex;
use tokio::sync::RwLock;

mod actions;
mod agent;
mod daemon;
mod debugger;
mod notifications;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

async fn async_main(startup_ack: Option<crate::daemon::StartupAck>) -> anyhow::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = rbw::config::Config::load()?;
    let timeout_duration = std::time::Duration::from_secs(config.lock_timeout);
    let sync_timeout_duration = std::time::Duration::from_secs(config.sync_interval);
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
    if sync_timeout_duration > std::time::Duration::ZERO {
        sync_timeout.set(sync_timeout_duration);
    }
    let notifications_handler = crate::notifications::NotificationsHandler::new();
    let state = Arc::new(Mutex::new(crate::state::State {
        inner: Arc::new(crate::state::InnerState {
            priv_key: RwLock::new(None),
            org_keys: RwLock::new(None),
            notifications_handler: RwLock::new(notifications_handler),
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            master_password_reprompt: RwLock::new(std::collections::HashSet::new()),
            master_password_reprompt_initialized: AtomicBool::new(false),
            config,
            last_environment: RwLock::new(rbw::protocol::Environment::default()),

            #[cfg(feature = "clipboard")]
            clipboard: Mutex::new(
                arboard::Clipboard::new()
                    .inspect_err(|e| {
                        log::warn!("couldn't create clipboard context: {e}");
                    })
                    .ok(),
            ),
        }),
    }));

    let agent = crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    tokio::try_join!(agent.run(listener), ssh_agent.run())?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    rbw::dirs::make_all()?;

    let startup_ack = daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    tokio::runtime::Runtime::new()?.block_on(async { async_main(startup_ack).await })?;

    Ok(())
}
