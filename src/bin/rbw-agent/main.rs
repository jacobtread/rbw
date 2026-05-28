use anyhow::Context as _;

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
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();

    let state = crate::state::State::new(config, timeout, sync_timeout);
    let agent = crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state);

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
