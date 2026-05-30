use anyhow::Context as _;
use rbw::actions::SessionParameters;
use sha2::Digest as _;

async fn getpin(
    pinentry: &str,
    desc: &str,
    prompt: &str,
    err: &Option<String>,
    environment: &rbw::protocol::Environment,
    grab: bool,
) -> anyhow::Result<rbw::locked::Password> {
    Ok(rbw::pinentry::getpin(pinentry, prompt, desc, err.as_deref(), environment, grab).await?)
}

async fn get_client_id(
    pinentry: &str,
    host: &str,
    err: &Option<String>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<rbw::locked::Password> {
    getpin(
        pinentry,
        "API key client__id",
        &format!("Log in to {host}"),
        err,
        environment,
        false,
    )
    .await
    .context("failed to read client_id from pinentry")
}

async fn get_client_secret(
    pinentry: &str,
    host: &str,
    err: &Option<String>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<rbw::locked::Password> {
    getpin(
        pinentry,
        "API key client__secret",
        &format!("Log in to {host}"),
        err,
        environment,
        false,
    )
    .await
    .context("failed to read client_secret from pinentry")
}

fn get_host(state: &crate::state::State) -> anyhow::Result<String> {
    let url_str = state.base_url();
    let url = reqwest::Url::parse(&url_str).context("failed to parse base url")?;
    let Some(host) = url.host_str() else {
        return Err(anyhow::anyhow!(
            "couldn't find host in rbw base url {url_str}"
        ));
    };

    Ok(host.to_string())
}

pub async fn register(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let db = load_db(&state).await.unwrap_or_else(|_| rbw::db::Db::new());

    if !db.needs_login() {
        return respond_ack(sock).await;
    }

    let host = get_host(&state)?;

    let email = state.email()?.to_string();

    let pinentry = state.pinentry().to_string();

    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = err_msg.map(|msg| format!("{msg} (attempt {i}/3)"));
        let client_id = get_client_id(&pinentry, &host, &err, environment).await?;
        let client_secret = get_client_secret(&pinentry, &host, &err, environment).await?;

        let apikey = rbw::locked::ApiKey::new(client_id, client_secret);

        match rbw::actions::register(&email, apikey).await {
            Ok(()) => {
                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) if i < 3 => {
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to log in to bitwarden instance"),
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn get_password(
    pinentry: &str,
    desc: &str,
    err: &Option<String>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<rbw::locked::Password> {
    getpin(pinentry, "Master Password", desc, err, environment, true)
        .await
        .context("failed to read password from pinentry")
}

async fn two_factor_required(
    state: &crate::state::State,
    pinentry: &str,
    email: &str,
    password: rbw::locked::Password,
    providers: Vec<rbw::api::TwoFactorProviderType>,
    sso_email_2fa_session_token: Option<String>,
    environment: &rbw::protocol::Environment,
    db: &mut rbw::db::Db,
) -> anyhow::Result<()> {
    let supported_types = [
        rbw::api::TwoFactorProviderType::Authenticator,
        rbw::api::TwoFactorProviderType::Yubikey,
        rbw::api::TwoFactorProviderType::Email,
    ];

    let Some(provider) = supported_types.into_iter().find(|p| providers.contains(p)) else {
        return Err(anyhow::anyhow!(
            "unsupported two factor methods: {providers:?}"
        ));
    };

    if provider == rbw::api::TwoFactorProviderType::Email {
        if let Some(token) = sso_email_2fa_session_token {
            rbw::actions::send_two_factor_email(email, &token).await?;
        }
    }

    let creds = two_factor(pinentry, environment, email, password.clone(), provider).await?;

    login_success(state.clone(), creds, password, db, email).await
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    let mut db = load_db(&state).await.unwrap_or_else(|_| rbw::db::Db::new());

    if !db.needs_login() {
        return respond_ack(sock).await;
    }

    let host = get_host(&state)?;

    let email = state.email()?.to_string();

    let pinentry = state.pinentry().to_string();

    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = err_msg
            .as_deref()
            .map(|msg| format!("{msg} (attempt {i}/3)"));

        let password =
            get_password(&pinentry, &format!("Log in to {host}"), &err, environment).await?;

        match rbw::actions::login(&email, password.clone(), None, None).await {
            Ok(creds) => {
                login_success(state.clone(), creds, password, &mut db, &email).await?;

                break;
            }
            Err(rbw::error::Error::TwoFactorRequired {
                providers,
                sso_email_2fa_session_token,
            }) => {
                two_factor_required(
                    &state,
                    &pinentry,
                    &email,
                    password,
                    providers,
                    sso_email_2fa_session_token,
                    environment,
                    &mut db,
                )
                .await?;

                break;
            }
            Err(rbw::error::Error::IncorrectPassword { message }) if i < 3 => {
                err_msg = Some(message);
            }
            Err(e) => return Err(e).context("failed to log in to bitwarden instance"),
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn get_code(
    pinentry: &str,
    provider: rbw::api::TwoFactorProviderType,
    err: &Option<String>,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<rbw::locked::Password> {
    getpin(
        pinentry,
        provider.header(),
        provider.message(),
        err,
        environment,
        provider.grab(),
    )
    .await
    .context("failed to read code from pinentry")
}

async fn two_factor(
    pinentry: &str,
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> anyhow::Result<SessionParameters> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = err_msg.map(|msg| format!("{msg} (attempt {i}/3)"));

        let code = get_code(pinentry, provider, &err, environment).await?;
        let code = std::str::from_utf8(code.password()).context("code was not valid utf8")?;

        match rbw::actions::login(email, password.clone(), Some(code), Some(provider)).await {
            Ok(creds) => return Ok(creds),
            Err(rbw::error::Error::IncorrectPassword { message }) if i < 3 => {
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) if i < 3 => {
                err_msg = Some("TOTP code is not a number".to_string());
            }
            Err(e) => return Err(e).context("failed to log in to bitwarden instance"),
        }
    }

    unreachable!()
}

async fn login_success(
    state: crate::state::State,
    creds: SessionParameters,
    password: rbw::locked::Password,
    db: &mut rbw::db::Db,
    email: &str,
) -> anyhow::Result<()> {
    db.apply_session_parameters(&creds);

    save_db(&state, db).await?;

    sync(None, &state).await?;

    let db = load_db(&state).await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(anyhow::anyhow!(
            "failed to find protected private key in db"
        ));
    };

    let res = rbw::actions::unlock(
        email,
        &password,
        &creds.crypto_params,
        &creds.protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            state.set_keys(keys, org_keys).await;
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

async fn unlock_state(
    state: &crate::state::State,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    if state.needs_unlock().await {
        let (db, email) = {
            let db = load_db(&state).await?;
            let email = state.email()?.to_string();
            (db, email)
        };

        let crypto_params = db.get_crypto_parameters()?;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!("failed to find protected key in db"));
        };

        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let pinentry = state.pinentry().to_string();
        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = err_msg.map(|msg| format!("{msg} (attempt {i}/3)"));

            let password = get_password(
                &pinentry,
                &format!("Unlock the local database for '{}'", rbw::dirs::profile()),
                &err,
                environment,
            )
            .await?;

            match rbw::actions::unlock(
                &email,
                &password,
                &crypto_params,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) if i < 3 => {
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: &crate::state::State,
    environment: &rbw::protocol::Environment,
) -> anyhow::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: &crate::state::State,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> anyhow::Result<()> {
    state.set_keys(keys, org_keys).await;

    Ok(())
}

pub async fn lock(sock: &mut crate::sock::Sock, state: crate::state::State) -> anyhow::Result<()> {
    state.clear().await;

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
) -> anyhow::Result<()> {
    if state.needs_unlock().await {
        return Err(anyhow::anyhow!("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: &crate::state::State,
) -> anyhow::Result<()> {
    let mut db = load_db(&state).await?;

    let Some(access_token) = &db.access_token else {
        anyhow::bail!("failed to find access token in db");
    };

    let Some(refresh_token) = &db.refresh_token else {
        anyhow::bail!("failed to find refresh token in db");
    };

    let (access_token, (protected_key, protected_private_key, protected_org_keys, entries)) =
        rbw::actions::sync(access_token, refresh_token)
            .await
            .context("failed to sync database from server")?;

    state.set_master_password_reprompt(&entries).await;

    db.update_access_token(access_token);

    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;

    save_db(&state, &db).await?;

    if let Err(e) = subscribe_to_notifications(&state).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

fn decrypt_entry_key(
    entry_key: Option<&str>,
    keys: &rbw::locked::Keys,
) -> anyhow::Result<Option<rbw::locked::Keys>> {
    entry_key
        .map(|ek| {
            let cs = rbw::cipherstring::CipherString::new(ek)
                .context("failed to parse individual item encryption key")?;
            Ok(rbw::locked::Keys::new(
                cs.decrypt_locked_symmetric(keys)
                    .context("failed to decrypt individual item encryption key")?,
            ))
        })
        .transpose()
}

async fn maybe_reprompt_password(
    state: &crate::state::State,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
) -> anyhow::Result<()> {
    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();

    if state
        .inner
        .master_password_reprompt
        .read()
        .await
        .contains(&master_password_reprompt)
    {
        let db = load_db(state).await?;

        let crypto_params = db.get_crypto_parameters()?;

        let Some(protected_key) = db.protected_key else {
            return Err(anyhow::anyhow!("failed to find protected key in db"));
        };

        let Some(protected_private_key) = db.protected_private_key else {
            return Err(anyhow::anyhow!(
                "failed to find protected private key in db"
            ));
        };

        let email = state.email()?;

        let pinentry = state.pinentry().to_string();
        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = err_msg.map(|msg| format!("{msg} (attempt {i}/3)"));

            // TODO: Remember somewhere that only GUI pinentry work, since this is a daemon.
            let password = get_password(
                &pinentry,
                "Accessing this entry requires the master password",
                &err,
                environment,
            )
            .await?;

            match rbw::actions::unlock(
                &email,
                &password,
                &crypto_params,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok(_) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) if i < 3 => {
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

async fn decrypt_cipher(
    state: crate::state::State,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<String> {
    if !state.master_password_reprompt_initialized() {
        let db = load_db(&state).await?;
        state.set_master_password_reprompt(&db.entries).await;
    }

    let Some(keys) = state.key(org_id).await else {
        return Err(anyhow::anyhow!(
            "failed to find decryption keys in in-memory state"
        ));
    };

    let entry_key = decrypt_entry_key(entry_key, keys.as_ref())?;

    maybe_reprompt_password(&state, environment, cipherstring).await?;

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;

    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys.as_ref(), entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let plaintext = decrypt_cipher(state, environment, cipherstring, entry_key, org_id).await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
    plaintext: &str,
    org_id: Option<&str>,
) -> anyhow::Result<()> {
    let Some(keys) = state.key(org_id).await else {
        return Err(anyhow::anyhow!(
            "failed to find encryption keys in in-memory state"
        ));
    };

    let cipherstring =
        rbw::cipherstring::CipherString::encrypt_symmetric(keys.as_ref(), plaintext.as_bytes())
            .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: crate::state::State,
    text: &str,
) -> anyhow::Result<()> {
    if let Some(clipboard) = &mut (*state.clipboard_mut().await) {
        clipboard
            .set_text(text)
            .map_err(|e| anyhow::anyhow!("couldn't store value to clipboard: {e}"))?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]

pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: crate::state::State,
    _text: &str,
) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

async fn respond_decrypt(sock: &mut crate::sock::Sock, plaintext: String) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(sock: &mut crate::sock::Sock, cipherstring: String) -> anyhow::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn load_db(state: &crate::state::State) -> anyhow::Result<rbw::db::Db> {
    let email = state.email()?;
    rbw::db::Db::load_async(&state.server_name(), email)
        .await
        .map_err(anyhow::Error::new)
}

async fn save_db(state: &crate::state::State, db: &rbw::db::Db) -> anyhow::Result<()> {
    let email = state.email()?;
    db.save_async(&state.server_name(), email)
        .await
        .map_err(anyhow::Error::new)
}

pub async fn subscribe_to_notifications(state: &crate::state::State) -> anyhow::Result<()> {
    if state.notifications_handler().await.is_connected() {
        return Ok(());
    }

    let (email, server_name, notifications_url) = {
        let email = state.email()?.to_string();
        let server_name = state.server_name();
        let notifications_url = state.notifications_url();
        (email, server_name, notifications_url)
    };

    let db = rbw::db::Db::load_async(&server_name, &email).await?;
    let access_token = db.access_token.context("Error getting access token")?;

    let websocket_url = format!("{}/hub?access_token={}", notifications_url, access_token)
        .replace("https://", "wss://");

    let mut nh = state.notifications_handler_mut().await;

    nh.connect(websocket_url)
        .await
        .err()
        .map_or_else(|| Ok(()), |err| Err(anyhow::anyhow!(err.to_string())))
}

pub async fn get_ssh_public_keys(state: crate::state::State) -> anyhow::Result<Vec<String>> {
    let environment = {
        let le = state.last_environment().await;
        state.set_timeout().await;
        le.clone()
    };

    unlock_state(&state, &environment).await?;

    let db = load_db(&state).await?;

    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

pub async fn find_ssh_private_key(
    state: crate::state::State,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> anyhow::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let le = state.last_environment().await;
        state.set_timeout().await;
        le.clone()
    };

    unlock_state(&state, &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db(&state).await?;

    for entry in db.entries {
        let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        else {
            continue;
        };

        let Some(public_key_enc) = public_key else {
            continue;
        };

        let public_key_plaintext = decrypt_cipher(
            state.clone(),
            &environment,
            public_key_enc,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )
        .await?;

        let public_key_bytes =
            ssh_agent_lib::ssh_key::PublicKey::from_openssh(&public_key_plaintext)?.to_bytes();

        if public_key_bytes != request_bytes {
            continue;
        }

        let private_key_enc = private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Matching entry has no private key"))?;

        let private_key_plaintext = decrypt_cipher(
            state.clone(),
            &environment,
            private_key_enc,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )
        .await?;

        return ssh_agent_lib::ssh_key::PrivateKey::from_openssh(private_key_plaintext)
            .map_err(anyhow::Error::new);
    }

    Err(anyhow::anyhow!("No matching private key found"))
}
