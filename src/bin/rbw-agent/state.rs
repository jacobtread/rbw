use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
};

use sha2::Digest as _;
#[cfg(feature = "clipboard")]
use tokio::sync::Mutex;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::notifications::NotificationsHandler;

pub struct InnerState {
    pub priv_key: RwLock<Option<Arc<rbw::locked::Keys>>>,
    pub org_keys: RwLock<Option<std::collections::HashMap<String, Arc<rbw::locked::Keys>>>>,
    pub notifications_handler: RwLock<NotificationsHandler>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub master_password_reprompt: RwLock<std::collections::HashSet<[u8; 32]>>,
    pub master_password_reprompt_initialized: AtomicBool,
    pub config: rbw::config::Config,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the rbw agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: RwLock<rbw::protocol::Environment>,

    #[cfg(feature = "clipboard")]
    pub clipboard: Mutex<Option<arboard::Clipboard>>,
}

pub struct State {
    pub inner: Arc<InnerState>,
}

impl State {
    pub async fn key(&self, org_id: Option<&str>) -> Option<Arc<rbw::locked::Keys>> {
        match org_id {
            Some(id) => self
                .inner
                .org_keys
                .read()
                .await
                .as_ref()
                .and_then(|h| h.get(id).cloned()),
            None => self.inner.priv_key.read().await.clone(),
        }
    }

    pub async fn set_priv_key(&self, priv_key: rbw::locked::Keys) {
        *self.inner.priv_key.write().await = Some(Arc::new(priv_key));
    }

    pub async fn set_org_keys(&self, org_keys: HashMap<String, rbw::locked::Keys>) {
        let org_keys: HashMap<String, Arc<rbw::locked::Keys>> = org_keys
            .into_iter()
            .map(|(k, v)| (k, Arc::new(v)))
            .collect();

        *self.inner.org_keys.write().await = Some(org_keys);
    }

    pub async fn needs_unlock(&self) -> bool {
        self.inner.priv_key.read().await.is_none() || self.inner.org_keys.read().await.is_none()
    }

    pub fn set_timeout(&self) {
        self.inner.timeout.set(self.inner.timeout_duration);
    }

    pub async fn notifications_handler(&self) -> RwLockReadGuard<'_, NotificationsHandler> {
        self.inner.notifications_handler.read().await
    }

    pub async fn notifications_handler_mut(&self) -> RwLockWriteGuard<'_, NotificationsHandler> {
        self.inner.notifications_handler.write().await
    }

    pub async fn clear(&mut self) {
        *self.inner.priv_key.write().await = None;
        *self.inner.org_keys.write().await = None;
        self.inner.timeout.clear();
    }

    pub fn set_sync_timeout(&self) {
        self.inner
            .sync_timeout
            .set(self.inner.sync_timeout_duration);
    }

    // the way we structure the client/agent split in rbw makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled. this set is only updated when the agent itself does
    // a sync, so it can't be bypassed by editing the on-disk file directly.
    // if the agent gets a request for any of those cipherstrings that it saw
    // marked as master password reprompt during the most recent sync, it
    // forces a reprompt.

    async fn add_mpr(&self, s: Option<&str>) {
        if let Some(s) = s {
            if !s.is_empty() {
                let mut hasher = sha2::Sha256::new();
                hasher.update(s);
                self.inner
                    .master_password_reprompt
                    .write()
                    .await
                    .insert(hasher.finalize().into());
            }
        }
    }

    pub async fn set_master_password_reprompt<T>(&self, entries: &[rbw::db::Entry<T>]) {
        self.inner.master_password_reprompt.write().await.clear();

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                rbw::db::EntryData::Login { password, totp, .. } => {
                    self.add_mpr(password.as_deref()).await;
                    self.add_mpr(totp.as_deref()).await;
                }
                rbw::db::EntryData::Card { number, code, .. } => {
                    self.add_mpr(number.as_deref()).await;
                    self.add_mpr(code.as_deref()).await;
                }
                rbw::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    self.add_mpr(ssn.as_deref()).await;
                    self.add_mpr(passport_number.as_deref()).await;
                }
                rbw::db::EntryData::SecureNote => {}
                rbw::db::EntryData::SshKey { private_key, .. } => {
                    self.add_mpr(private_key.as_deref()).await;
                }
            }

            for field in &entry.fields {
                if field.ty == Some(rbw::api::FieldType::Hidden) {
                    self.add_mpr(field.value.as_deref()).await;
                }
            }
        }

        self.inner
            .master_password_reprompt_initialized
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn master_password_reprompt_initialized(&self) -> bool {
        self.inner
            .master_password_reprompt_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn last_environment(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, rbw::protocol::Environment> {
        self.inner.last_environment.read().await
    }

    pub async fn set_last_environment(&self, environment: rbw::protocol::Environment) {
        *self.inner.last_environment.write().await = environment;
    }

    pub fn email(&self) -> anyhow::Result<&str> {
        self.inner
            .config
            .email
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("failed to find email address in config"))
    }

    pub fn base_url(&self) -> String {
        self.inner.config.base_url()
    }

    pub fn pinentry(&self) -> &str {
        &self.inner.config.pinentry
    }

    pub fn notifications_url(&self) -> String {
        self.inner.config.notifications_url()
    }

    pub fn server_name(&self) -> String {
        self.inner.config.server_name()
    }

    #[cfg(feature = "clipboard")]
    pub async fn clipboard_mut(&self) -> tokio::sync::MutexGuard<'_, Option<arboard::Clipboard>> {
        self.inner.clipboard.lock().await
    }

    pub fn confirm_ssh(&self) -> bool {
        self.inner.config.confirm_ssh.is_some_and(|o| o)
    }
}
