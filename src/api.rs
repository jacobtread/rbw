// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use std::{
    collections::HashMap,
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use crate::{
    actions::CryptoParameters,
    db::{Encrypted, EntryData},
    prelude::*,
};

use rand::distr::SampleString as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use tokio::sync::mpsc;

use crate::json::{DeserializeJsonWithPath as _, DeserializeJsonWithPathAsync as _};

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, Debug, Copy, Clone, PartialEq, Eq,
)]
#[repr(u8)]
pub enum UriMatchType {
    Domain = 0,
    Host = 1,
    StartsWith = 2,
    Exact = 3,
    RegularExpression = 4,
    Never = 5,
}

impl Display for UriMatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::enum_glob_use)]
        use UriMatchType::*;
        let s = match self {
            Domain => "domain",
            Host => "host",
            StartsWith => "starts_with",
            Exact => "exact",
            RegularExpression => "regular_expression",
            Never => "never",
        };
        write!(f, "{s}")
    }
}

struct IntegerStringVisitor<T>(std::marker::PhantomData<T>);

impl<T> serde::de::Visitor<'_> for IntegerStringVisitor<T>
where
    T: TryFrom<u64> + FromStr,
    <T as TryFrom<u64>>::Error: Display,
    <T as FromStr>::Err: Display,
{
    type Value = T;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("integer or string")
    }

    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<T, E> {
        T::try_from(v).map_err(serde::de::Error::custom)
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<T, E> {
        v.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

impl TwoFactorProviderType {
    pub fn message(&self) -> &str {
        match *self {
            Self::Authenticator => {
                "Enter the 6 digit verification code from your authenticator app."
            }
            Self::Yubikey => "Insert your Yubikey and push the button.",
            Self::Email => "Enter the PIN you received via email.",
            _ => "Enter the code.",
        }
    }

    pub fn header(&self) -> &str {
        match *self {
            Self::Authenticator => "Authenticator App",
            Self::Yubikey => "Yubikey",
            Self::Email => "Email Code",
            _ => "Two Factor Authentication",
        }
    }

    pub fn grab(&self) -> bool {
        !matches!(self, Self::Email)
    }
}

impl<'de> Deserialize<'de> for TwoFactorProviderType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(IntegerStringVisitor(std::marker::PhantomData))
    }
}

impl TryFrom<u64> for TwoFactorProviderType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Authenticator),
            1 => Ok(Self::Email),
            2 => Ok(Self::Duo),
            3 => Ok(Self::Yubikey),
            4 => Ok(Self::U2f),
            5 => Ok(Self::Remember),
            6 => Ok(Self::OrganizationDuo),
            7 => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl FromStr for TwoFactorProviderType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Authenticator),
            "1" => Ok(Self::Email),
            "2" => Ok(Self::Duo),
            "3" => Ok(Self::Yubikey),
            "4" => Ok(Self::U2f),
            "5" => Ok(Self::Remember),
            "6" => Ok(Self::OrganizationDuo),
            "7" => Ok(Self::WebAuthn),
            _ => Err(Error::InvalidTwoFactorProvider { ty: ty.to_string() }),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum KdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

impl<'de> Deserialize<'de> for KdfType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(IntegerStringVisitor(std::marker::PhantomData))
    }
}

impl TryFrom<u64> for KdfType {
    type Error = Error;

    fn try_from(ty: u64) -> Result<Self> {
        match ty {
            0 => Ok(Self::Pbkdf2),
            1 => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType {
                ty: format!("{ty}"),
            }),
        }
    }
}

impl FromStr for KdfType {
    type Err = Error;

    fn from_str(ty: &str) -> Result<Self> {
        match ty {
            "0" => Ok(Self::Pbkdf2),
            "1" => Ok(Self::Argon2id),
            _ => Err(Error::InvalidKdfType { ty: ty.to_string() }),
        }
    }
}

impl Serialize for KdfType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            Self::Pbkdf2 => "0",
            Self::Argon2id => "1",
        };
        serializer.serialize_str(s)
    }
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, Debug, Copy, Clone, PartialEq, Eq,
)]
#[repr(u8)]
pub enum CipherRepromptType {
    None = 0,
    Password = 1,
}

#[derive(Deserialize, Debug)]
struct PreloginRes {
    #[serde(rename = "Kdf", alias = "kdf")]
    kdf: KdfType,
    #[serde(rename = "KdfIterations", alias = "kdfIterations")]
    kdf_iterations: u32,
    #[serde(rename = "KdfMemory", alias = "kdfMemory")]
    kdf_memory: Option<u32>,
    #[serde(rename = "KdfParallelism", alias = "kdfParallelism")]
    kdf_parallelism: Option<u32>,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum ConnectTokenAuth<'a> {
    Password {
        username: &'a str,
        password: &'a str,
    },
    AuthCode {
        code: &'a str,
        code_verifier: &'a str,
        redirect_uri: &'a str,
    },
    ClientCredentials {
        username: &'a str,
        client_secret: &'a str,
    },
}

#[derive(Serialize, Debug)]
struct ConnectTokenReq<'a> {
    grant_type: &'a str,
    scope: &'a str,
    client_id: &'a str,
    #[serde(rename = "deviceType")]
    device_type: u32,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: &'a str,
    #[serde(rename = "deviceName")]
    device_name: &'a str,
    #[serde(rename = "devicePushToken")]
    device_push_token: &'a str,
    #[serde(rename = "twoFactorToken")]
    two_factor_token: Option<&'a str>,
    #[serde(rename = "twoFactorProvider")]
    two_factor_provider: Option<u32>,
    #[serde(flatten)]
    auth: ConnectTokenAuth<'a>,
}

#[derive(Deserialize, Debug)]
struct ConnectTokenRes {
    access_token: String,
    refresh_token: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(Deserialize, Debug)]
struct ConnectErrorRes {
    error: String,
    error_description: Option<String>,
    #[serde(rename = "ErrorModel", alias = "errorModel")]
    error_model: Option<ConnectErrorResErrorModel>,
    #[serde(rename = "TwoFactorProviders", alias = "twoFactorProviders")]
    two_factor_providers: Option<Vec<TwoFactorProviderType>>,
    #[serde(rename = "SsoEmail2faSessionToken", alias = "ssoEmail2faSessionToken")]
    sso_email_2fa_session_token: Option<String>,
}

impl TryFrom<ConnectErrorRes> for Error {
    type Error = ConnectErrorRes;

    fn try_from(value: ConnectErrorRes) -> std::result::Result<Self, Self::Error> {
        let error_desc = value.error_description.as_deref();
        match value.error.as_str() {
            "invalid_grant" => match error_desc {
                Some("invalid_username_or_password") => {
                    if let Some(error_model) = value.error_model.as_ref() {
                        let message = error_model.message.as_str().to_string();
                        return Ok(Error::IncorrectPassword { message });
                    }
                }
                Some("Two factor required.") => {
                    if let Some(providers) = value.two_factor_providers.as_ref() {
                        return Ok(Error::TwoFactorRequired {
                            providers: providers.clone(),
                            sso_email_2fa_session_token: value.sso_email_2fa_session_token.clone(),
                        });
                    }
                }
                Some("Captcha required.") => {
                    return Ok(Error::RegistrationRequired);
                }
                _ => {}
            },
            "invalid_client" => {
                return Ok(Error::IncorrectApiKey);
            }
            "" => {
                // bitwarden_rs returns an empty error and error_description for
                // this case, for some reason
                if error_desc.is_none() || error_desc == Some("") {
                    if let Some(error_model) = value.error_model.as_ref() {
                        let message = error_model.message.clone();
                        match message.as_str() {
                            "Username or password is incorrect. Try again"
                            | "TOTP code is not a number" => {
                                return Ok(Error::IncorrectPassword { message });
                            }
                            s => {
                                if s.starts_with("Invalid TOTP code! Server time: ") {
                                    return Ok(Error::IncorrectPassword { message });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        Err(value)
    }
}

#[derive(Deserialize, Debug)]
struct ConnectErrorResErrorModel {
    #[serde(rename = "Message", alias = "message")]
    message: String,
}

#[derive(Deserialize, Debug)]
struct ConnectRefreshTokenRes {
    access_token: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherLoginUri {
    #[serde(rename = "Uri", alias = "uri")]
    uri: Option<String>,
    #[serde(rename = "Match", alias = "match")]
    match_type: Option<UriMatchType>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherLogin {
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
    #[serde(rename = "Totp", alias = "totp")]
    totp: Option<String>,
    #[serde(rename = "Uris", alias = "uris")]
    uris: Option<Vec<CipherLoginUri>>,
}

impl From<CipherLogin> for EntryData {
    fn from(value: CipherLogin) -> Self {
        Self::Login {
            username: value.username,
            password: value.password,
            totp: value.totp,
            uris: value.uris.map_or_else(Vec::new, |uris| {
                uris.into_iter()
                    .filter_map(|uri| {
                        uri.uri.map(|s| crate::db::Uri {
                            uri: s,
                            match_type: uri.match_type,
                        })
                    })
                    .collect()
            }),
        }
    }
}

impl TryFrom<EntryData> for CipherLogin {
    type Error = ();

    fn try_from(value: EntryData) -> std::result::Result<Self, Self::Error> {
        let EntryData::Login {
            username,
            password,
            totp,
            uris,
        } = value
        else {
            return Err(());
        };

        Ok(CipherLogin {
            username,
            password,
            totp,
            uris: if uris.is_empty() {
                None
            } else {
                Some(
                    uris.iter()
                        .map(|s| CipherLoginUri {
                            uri: Some(s.uri.clone()),
                            match_type: s.match_type,
                        })
                        .collect(),
                )
            },
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherCard {
    #[serde(rename = "CardholderName", alias = "cardholderName")]
    cardholder_name: Option<String>,
    #[serde(rename = "Number", alias = "number")]
    number: Option<String>,
    #[serde(rename = "Brand", alias = "brand")]
    brand: Option<String>,
    #[serde(rename = "ExpMonth", alias = "expMonth")]
    exp_month: Option<String>,
    #[serde(rename = "ExpYear", alias = "expYear")]
    exp_year: Option<String>,
    #[serde(rename = "Code", alias = "code")]
    code: Option<String>,
}

impl From<CipherCard> for EntryData {
    fn from(value: CipherCard) -> Self {
        Self::Card {
            cardholder_name: value.cardholder_name,
            number: value.number,
            brand: value.brand,
            exp_month: value.exp_month,
            exp_year: value.exp_year,
            code: value.code,
        }
    }
}

impl TryFrom<EntryData> for CipherCard {
    type Error = ();

    fn try_from(value: EntryData) -> std::result::Result<Self, Self::Error> {
        let EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } = value
        else {
            return Err(());
        };

        Ok(Self {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherIdentity {
    #[serde(rename = "Title", alias = "title")]
    title: Option<String>,
    #[serde(rename = "FirstName", alias = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "MiddleName", alias = "middleName")]
    middle_name: Option<String>,
    #[serde(rename = "LastName", alias = "lastName")]
    last_name: Option<String>,
    #[serde(rename = "Address1", alias = "address1")]
    address1: Option<String>,
    #[serde(rename = "Address2", alias = "address2")]
    address2: Option<String>,
    #[serde(rename = "Address3", alias = "address3")]
    address3: Option<String>,
    #[serde(rename = "City", alias = "city")]
    city: Option<String>,
    #[serde(rename = "State", alias = "state")]
    state: Option<String>,
    #[serde(rename = "PostalCode", alias = "postalCode")]
    postal_code: Option<String>,
    #[serde(rename = "Country", alias = "country")]
    country: Option<String>,
    #[serde(rename = "Phone", alias = "phone")]
    phone: Option<String>,
    #[serde(rename = "Email", alias = "email")]
    email: Option<String>,
    #[serde(rename = "SSN", alias = "ssn")]
    ssn: Option<String>,
    #[serde(rename = "LicenseNumber", alias = "licenseNumber")]
    license_number: Option<String>,
    #[serde(rename = "PassportNumber", alias = "passportNumber")]
    passport_number: Option<String>,
    #[serde(rename = "Username", alias = "username")]
    username: Option<String>,
}

impl From<CipherIdentity> for EntryData {
    fn from(value: CipherIdentity) -> Self {
        Self::Identity {
            title: value.title,
            first_name: value.first_name,
            middle_name: value.middle_name,
            last_name: value.last_name,
            address1: value.address1,
            address2: value.address2,
            address3: value.address3,
            city: value.city,
            state: value.state,
            postal_code: value.postal_code,
            country: value.country,
            phone: value.phone,
            email: value.email,
            ssn: value.ssn,
            license_number: value.license_number,
            passport_number: value.passport_number,
            username: value.username,
        }
    }
}

impl TryFrom<EntryData> for CipherIdentity {
    type Error = ();

    fn try_from(value: EntryData) -> std::result::Result<Self, Self::Error> {
        let EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } = value
        else {
            return Err(());
        };

        Ok(Self {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherSshKey {
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: Option<String>,
    #[serde(rename = "PublicKey", alias = "publicKey")]
    public_key: Option<String>,
    #[serde(rename = "Fingerprint", alias = "keyFingerprint")]
    fingerprint: Option<String>,
}

impl From<CipherSshKey> for EntryData {
    fn from(value: CipherSshKey) -> Self {
        Self::SshKey {
            private_key: value.private_key,
            public_key: value.public_key,
            fingerprint: value.fingerprint,
        }
    }
}

impl TryFrom<EntryData> for CipherSshKey {
    type Error = ();

    fn try_from(value: EntryData) -> std::result::Result<Self, Self::Error> {
        let EntryData::SshKey {
            private_key,
            public_key,
            fingerprint,
        } = value
        else {
            return Err(());
        };

        Ok(Self {
            private_key,
            public_key,
            fingerprint,
        })
    }
}

// this is just a name and some notes, both of which are already on the cipher
// object
#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherSecureNote {}

impl From<CipherSecureNote> for EntryData {
    fn from(_value: CipherSecureNote) -> Self {
        Self::SecureNote
    }
}

impl TryFrom<EntryData> for CipherSecureNote {
    type Error = ();

    fn try_from(value: EntryData) -> std::result::Result<Self, Self::Error> {
        let EntryData::SecureNote = value else {
            return Err(());
        };

        Ok(Self {})
    }
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(u16)]
pub enum FieldType {
    Text = 0,
    Hidden = 1,
    Boolean = 2,
    Linked = 3,
}

#[derive(
    serde_repr::Serialize_repr, serde_repr::Deserialize_repr, Debug, Clone, Copy, PartialEq, Eq,
)]
#[repr(u16)]
pub enum LinkedIdType {
    LoginUsername = 100,
    LoginPassword = 101,
    CardCardholderName = 300,
    CardExpMonth = 301,
    CardExpYear = 302,
    CardCode = 303,
    CardBrand = 304,
    CardNumber = 305,
    IdentityTitle = 400,
    IdentityMiddleName = 401,
    IdentityAddress1 = 402,
    IdentityAddress2 = 403,
    IdentityAddress3 = 404,
    IdentityCity = 405,
    IdentityState = 406,
    IdentityPostalCode = 407,
    IdentityCountry = 408,
    IdentityCompany = 409,
    IdentityEmail = 410,
    IdentityPhone = 411,
    IdentitySsn = 412,
    IdentityUsername = 413,
    IdentityPassportNumber = 414,
    IdentityLicenseNumber = 415,
    IdentityFirstName = 416,
    IdentityLastName = 417,
    IdentityFullName = 418,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct CipherDynamicField {
    #[serde(rename = "Type", alias = "type")]
    ty: Option<FieldType>,
    #[serde(rename = "Name", alias = "name")]
    name: Option<String>,
    #[serde(rename = "Value", alias = "value")]
    value: Option<String>,
    #[serde(rename = "LinkedId", alias = "linkedId")]
    linked_id: Option<LinkedIdType>,
}

impl From<CipherDynamicField> for crate::db::DynamicField {
    fn from(value: CipherDynamicField) -> Self {
        Self {
            ty: value.ty,
            name: value.name,
            value: value.value,
            linked_id: value.linked_id,
        }
    }
}

impl From<crate::db::DynamicField> for CipherDynamicField {
    fn from(value: crate::db::DynamicField) -> Self {
        Self {
            ty: value.ty,
            name: value.name,
            value: value.value,
            linked_id: value.linked_id,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SyncResPasswordHistory {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SyncResCipher {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "FolderId", alias = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "OrganizationId", alias = "organizationId")]
    organization_id: Option<String>,
    #[serde(rename = "Name", alias = "name")]
    name: String,
    #[serde(rename = "Login", alias = "login")]
    login: Option<CipherLogin>,
    #[serde(rename = "Card", alias = "card")]
    card: Option<CipherCard>,
    #[serde(rename = "Identity", alias = "identity")]
    identity: Option<CipherIdentity>,
    #[serde(rename = "SecureNote", alias = "secureNote")]
    secure_note: Option<CipherSecureNote>,
    #[serde(rename = "SshKey", alias = "sshKey")]
    ssh_key: Option<CipherSshKey>,
    #[serde(rename = "Notes", alias = "notes")]
    notes: Option<String>,
    #[serde(rename = "PasswordHistory", alias = "passwordHistory")]
    password_history: Option<Vec<SyncResPasswordHistory>>,
    #[serde(rename = "Fields", alias = "fields")]
    fields: Option<Vec<CipherDynamicField>>,
    #[serde(rename = "DeletedDate", alias = "deletedDate")]
    deleted_date: Option<String>,
    #[serde(rename = "Key", alias = "key")]
    key: Option<String>,
    #[serde(rename = "Reprompt", alias = "reprompt")]
    reprompt: CipherRepromptType,
}

impl SyncResCipher {
    fn to_entry(self, folders: &[SyncResFolder]) -> Option<crate::db::Entry<Encrypted>> {
        if self.deleted_date.is_some() {
            return None;
        }
        let history = self
            .password_history
            //.as_ref()
            .map_or_else(Vec::new, |history| {
                history
                    .into_iter()
                    .filter_map(|entry| {
                        // Gets rid of entries with a non-existent
                        // password
                        entry.password.map(|p| crate::db::HistoryEntry {
                            last_used_date: entry.last_used_date,
                            password: p,
                        })
                    })
                    .collect()
            });

        let (folder, folder_id) = self.folder_id.map_or((None, None), |folder_id| {
            let mut folder_name = None;
            for folder in folders {
                if folder.id == folder_id {
                    folder_name = Some(folder.name.clone());
                }
            }
            (folder_name, Some(folder_id))
        });

        let data = if let Some(login) = self.login {
            login.into()
        } else if let Some(card) = self.card {
            card.into()
        } else if let Some(identity) = self.identity {
            identity.into()
        } else if let Some(secure_note) = self.secure_note {
            secure_note.into()
        } else if let Some(ssh_key) = self.ssh_key {
            ssh_key.into()
        } else {
            return None;
        };

        let fields: Vec<crate::db::DynamicField> = self.fields.map_or_else(Vec::new, |fields| {
            fields.into_iter().map(|field| field.into()).collect()
        });

        Some(crate::db::Entry::<Encrypted> {
            id: self.id,
            org_id: self.organization_id,
            folder,
            folder_id: folder_id,
            name: self.name,
            data,
            fields,
            notes: self.notes,
            history,
            key: self.key,
            master_password_reprompt: self.reprompt,
            _state: std::marker::PhantomData,
        })
    }
}

#[derive(Deserialize, Debug)]
struct SyncResProfile {
    #[serde(rename = "Key", alias = "key")]
    key: String,
    #[serde(rename = "PrivateKey", alias = "privateKey")]
    private_key: String,
    #[serde(rename = "Organizations", alias = "organizations")]
    organizations: Vec<SyncResProfileOrganization>,
}

#[derive(Deserialize, Debug)]
struct SyncResProfileOrganization {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Key", alias = "key")]
    key: String,
}

#[derive(Deserialize, Debug, Clone)]
struct SyncResFolder {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(Deserialize, Debug)]
struct SyncRes {
    #[serde(rename = "Ciphers", alias = "ciphers")]
    ciphers: Vec<SyncResCipher>,
    #[serde(rename = "Profile", alias = "profile")]
    profile: SyncResProfile,
    #[serde(rename = "Folders", alias = "folders")]
    folders: Vec<SyncResFolder>,
}

#[derive(Serialize, Debug)]
struct CiphersPostReq<'a> {
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    name: String,
    notes: Option<String>,
    #[serde(flatten)]
    data: EntryDataWire<'a>, // use lifetime parameter on the struct instead
}

#[derive(Serialize, Debug)]
struct CiphersPutReq<'a> {
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    organization_id: Option<String>,
    name: String,
    notes: Option<String>,
    #[serde(flatten)]
    data: EntryDataWire<'a>,
    fields: Vec<CipherDynamicField>,
    #[serde(rename = "passwordHistory")]
    password_history: Vec<CiphersPutReqHistory>,
}

#[derive(Serialize, Debug)]
struct CiphersPutReqHistory {
    #[serde(rename = "LastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password")]
    password: String,
}

#[derive(Debug)]
struct EntryDataWire<'a>(&'a EntryData);

impl Serialize for EntryDataWire<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        let data = self.0.clone();

        match self.0 {
            EntryData::Login { .. } => {
                map.serialize_entry("type", &1u32)?;
                map.serialize_entry("login", &TryInto::<CipherLogin>::try_into(data).unwrap())?;
            }
            EntryData::Card { .. } => {
                map.serialize_entry("type", &3u32)?;
                map.serialize_entry("card", &TryInto::<CipherCard>::try_into(data).unwrap())?;
            }
            EntryData::Identity { .. } => {
                map.serialize_entry("type", &4u32)?;
                map.serialize_entry(
                    "identity",
                    &TryInto::<CipherIdentity>::try_into(data).unwrap(),
                )?;
            }
            EntryData::SecureNote => {
                map.serialize_entry("type", &2u32)?;
                map.serialize_entry(
                    "secureNote",
                    &TryInto::<CipherSecureNote>::try_into(data).unwrap(),
                )?;
            }
            EntryData::SshKey { .. } => {
                // TODO: Not entirely true now
                return Err(serde::ser::Error::custom("SshKey not supported"));
            }
        }
        map.end()
    }
}

#[derive(Deserialize, Debug)]
struct FoldersResData {
    #[serde(rename = "Id", alias = "id")]
    id: String,
    #[serde(rename = "Name", alias = "name")]
    name: String,
}

#[derive(Deserialize, Debug)]
struct FoldersRes {
    #[serde(rename = "Data", alias = "data")]
    data: Vec<FoldersResData>,
}

// Used for the Bitwarden-Client-Name header. Accepted values:
// https://github.com/bitwarden/server/blob/main/src/Core/Enums/BitwardenClient.cs
const BITWARDEN_CLIENT: &str = "cli";

// DeviceType.LinuxDesktop, as per Bitwarden API device types.
const DEVICE_TYPE: u8 = 8;

enum ClientRequest<'a> {
    Prelogin(&'a str),
    ConnectToken(ConnectTokenReq<'a>),
    Login(ConnectTokenReq<'a>, &'a str),
    SendEmailLogin(&'a str, &'a str, &'a str),
    Sync(&'a str),
    ExchangeRefreshToken(&'a str),
}

impl<'a> ClientRequest<'a> {
    async fn req(self, client: &Client) -> Result<reqwest::Response> {
        let http_client = client.reqwest_client().await?;

        let rb = match self {
            Self::Prelogin(email) => http_client
                .post(client.identity_url("/accounts/prelogin"))
                .json(&serde_json::json!({"email": email})),
            Self::ConnectToken(r) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&r),
            Self::Login(r, email) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&r)
                .header("auth-email", crate::base64::encode_url_safe_no_pad(email)),
            Self::SendEmailLogin(email, device_identifier, sso_email_2fa_session_token) => {
                http_client
                    .post(client.api_url("/two-factor/send-email-login"))
                    .json(&serde_json::json!({
                        "email": email,
                        "DeviceIdentifier": device_identifier,
                        "SsoEmail2faSessionToken": sso_email_2fa_session_token
                    }))
                    .header("auth-email", crate::base64::encode_url_safe_no_pad(email))
            }
            Self::Sync(access_token) => http_client
                .get(client.api_url("/sync"))
                .header("Authorization", format!("Bearer {access_token}"))
                // This is necessary for vaultwarden to include the ssh keys in the response
                .header("Bitwarden-Client-Version", "2024.12.0"),
            Self::ExchangeRefreshToken(refresh_token) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", "cli"),
                    ("refresh_token", refresh_token),
                ]),
        };

        Ok(rb.send().await?)
    }
}

enum ClientBlockingRequest<'a> {
    Add(&'a str, CiphersPostReq<'a>),
    Edit(&'a str, &'a str, CiphersPutReq<'a>),
    Remove(&'a str, &'a str),
    Folders(&'a str),
    CreateFolder(&'a str, &'a str),
    ExchangeRefreshToken(&'a str),
}

impl<'a> ClientBlockingRequest<'a> {
    fn req(self, client: &Client) -> Result<reqwest::blocking::Response> {
        let http_client = reqwest::blocking::Client::new();

        let rb = match self {
            Self::Add(access_token, r) => http_client
                .post(client.api_url("/ciphers"))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&r),
            Self::Edit(access_token, id, r) => http_client
                .put(client.api_url(&format!("/ciphers/{id}")))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&r),
            Self::Remove(access_token, id) => http_client
                .delete(client.api_url(&format!("/ciphers/{id}")))
                .header("Authorization", format!("Bearer {access_token}")),
            Self::Folders(access_token) => http_client
                .get(client.api_url("/folders"))
                .header("Authorization", format!("Bearer {access_token}")),
            Self::CreateFolder(access_token, name) => http_client
                .post(client.api_url("/folders"))
                .header("Authorization", format!("Bearer {access_token}"))
                .json(&serde_json::json!({"name": name})),
            Self::ExchangeRefreshToken(refresh_token) => http_client
                .post(client.identity_url("/connect/token"))
                .form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", "cli"),
                    ("refresh_token", refresh_token),
                ]),
        };

        Ok(rb.send()?)
    }
}

#[derive(Debug)]
pub struct Client {
    base_url: String,
    identity_url: String,
    ui_url: String,
    client_cert_path: Option<PathBuf>,
}

impl Client {
    pub fn new(
        base_url: &str,
        identity_url: &str,
        ui_url: &str,
        client_cert_path: Option<&Path>,
    ) -> Self {
        Self {
            base_url: base_url.to_string(),
            identity_url: identity_url.to_string(),
            ui_url: ui_url.to_string(),
            client_cert_path: client_cert_path.map(Path::to_path_buf),
        }
    }

    async fn reqwest_client(&self) -> Result<reqwest::Client> {
        let mut default_headers = axum::http::HeaderMap::new();
        default_headers.insert(
            "Bitwarden-Client-Name",
            axum::http::HeaderValue::from_static(BITWARDEN_CLIENT),
        );
        default_headers.insert(
            "Bitwarden-Client-Version",
            axum::http::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        default_headers.append(
            "Device-Type",
            // unwrap is safe here because DEVICE_TYPE is a number and digits
            // are valid ASCII
            axum::http::HeaderValue::from_str(&DEVICE_TYPE.to_string()).unwrap(),
        );
        let user_agent = format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        if let Some(client_cert_path) = self.client_cert_path.as_ref() {
            let buf =
                tokio::fs::read(client_cert_path)
                    .await
                    .map_err(|e| Error::LoadClientCert {
                        source: e,
                        file: client_cert_path.clone(),
                    })?;
            let pem = reqwest::Identity::from_pem(&buf)
                .map_err(|e| Error::CreateReqwestClient { source: e })?;
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .identity(pem)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        } else {
            Ok(reqwest::Client::builder()
                .user_agent(user_agent)
                .default_headers(default_headers)
                .build()
                .map_err(|e| Error::CreateReqwestClient { source: e })?)
        }
    }

    pub async fn prelogin(&self, email: &str) -> Result<CryptoParameters> {
        let res: PreloginRes = ClientRequest::Prelogin(email)
            .req(self)
            .await?
            .json_with_path()
            .await?;

        Ok(CryptoParameters {
            kdf: res.kdf,
            iterations: res.kdf_iterations,
            memory: res.kdf_memory,
            parallelism: res.kdf_parallelism,
        })
    }

    async fn check_connect_token_res(res: reqwest::Response) -> Result<reqwest::Response> {
        match res.status() {
            reqwest::StatusCode::OK => Ok(res),
            status => match res.text().await {
                Ok(body) => match body.clone().json_with_path::<ConnectErrorRes>() {
                    Ok(err) => match err.try_into() {
                        Ok(e) => Err(e),
                        Err(err) => {
                            log::warn!("unexpected error received during login: {err:?}");
                            Err(Error::RequestFailed {
                                status: status.as_u16(),
                            })
                        }
                    },
                    Err(e) => {
                        log::warn!("{e}: {body}");
                        Err(Error::RequestFailed {
                            status: status.as_u16(),
                        })
                    }
                },
                Err(e) => {
                    log::warn!("failed to read response body: {e}");
                    Err(Error::RequestFailed {
                        status: status.as_u16(),
                    })
                }
            },
        }
    }

    pub async fn register(
        &self,
        email: &str,
        device_id: &str,
        apikey: &crate::locked::ApiKey,
    ) -> Result<()> {
        let connect_req = ConnectTokenReq {
            auth: ConnectTokenAuth::ClientCredentials {
                username: &email,
                client_secret: &String::from_utf8(apikey.client_secret().to_vec()).unwrap(),
            },
            grant_type: "client_credentials",
            scope: "api",
            // XXX unwraps here are not necessarily safe
            client_id: &String::from_utf8(apikey.client_id().to_vec()).unwrap(),
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id,
            device_name: "rbw",
            device_push_token: "",
            two_factor_token: None,
            two_factor_provider: None,
        };

        let res = ClientRequest::ConnectToken(connect_req).req(self).await?;

        Self::check_connect_token_res(res).await?;

        Ok(())
    }

    pub async fn login(
        &self,
        email: &str,
        sso_id: Option<&str>,
        device_id: &str,
        password_hash: &crate::locked::PasswordHash,
        two_factor_token: Option<&str>,
        two_factor_provider: Option<TwoFactorProviderType>,
    ) -> Result<(String, String, String)> {
        let (auth, grant_type, scope) = match sso_id {
            Some(sso_id) => {
                let (sso_code, sso_code_verifier, callback_url) =
                    self.obtain_sso_code(sso_id).await?;
                (
                    ConnectTokenAuth::AuthCode {
                        code: &sso_code.clone(),
                        code_verifier: &sso_code_verifier.clone(),
                        redirect_uri: &callback_url.clone(),
                    },
                    "authorization_code",
                    "api offline_access",
                )
            }
            None => (
                ConnectTokenAuth::Password {
                    username: email,
                    password: &crate::base64::encode(password_hash.hash()),
                },
                "password",
                "api offline_access",
            ),
        };

        let connect_req = ConnectTokenReq {
            auth,
            grant_type: grant_type,
            scope: scope,
            client_id: "cli",
            device_type: u32::from(DEVICE_TYPE),
            device_identifier: device_id,
            device_name: "rbw",
            device_push_token: "",
            two_factor_token: two_factor_token,
            two_factor_provider: two_factor_provider.map(|ty| ty as u32),
        };

        let res = ClientRequest::Login(connect_req, email).req(self).await?;

        let res = Self::check_connect_token_res(res).await?;

        let connect_res: ConnectTokenRes = res.json_with_path().await?;

        Ok((
            connect_res.access_token,
            connect_res.refresh_token,
            connect_res.key,
        ))
    }

    pub async fn send_email_login(
        &self,
        email: &str,
        device_id: &str,
        sso_email_2fa_session_token: &str,
    ) -> Result<()> {
        let res = ClientRequest::SendEmailLogin(email, device_id, sso_email_2fa_session_token)
            .req(self)
            .await?;

        if res.status() == reqwest::StatusCode::OK {
            Ok(())
        } else {
            let code = res.status().as_u16();
            log::warn!("{code}: {:?}", res.text().await);
            Err(Error::RequestFailed { status: code })
        }
    }

    async fn obtain_sso_code(&self, sso_id: &str) -> Result<(String, String, String)> {
        let state = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);
        let sso_code_verifier = rand::distr::Alphanumeric.sample_string(&mut rand::rng(), 64);

        let mut hasher = sha2::Sha256::new();
        hasher.update(&sso_code_verifier);
        let code_challenge = crate::base64::encode_url_safe_no_pad(hasher.finalize());

        let port = find_free_port(8065, 8070).await?;

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .map_err(|e| Error::CreateSSOCallbackServer { err: e })?;

        let callback_server = start_sso_callback_server(listener, state.as_str());

        let callback_url = "http://localhost:".to_string() + port.to_string().as_str();

        open::that(
            self.ui_url.clone()
                + "/#/sso?clientId="
                + "cli"
                + "&redirectUri="
                + urlencoding::encode(callback_url.as_str())
                    .into_owned()
                    .as_str()
                + "&state="
                + state.as_str()
                + "&codeChallenge="
                + code_challenge.as_str()
                + "&identifier="
                + sso_id,
        )
        .map_err(|e| Error::FailedToOpenWebBrowser { err: e })?;
        // TODO: probably it'd be better to display the URL in the console if the automatic
        // open operation fails, instead of failing the whole process? E.g. docker container
        // case

        let sso_code = callback_server.await?;

        Ok((sso_code, sso_code_verifier, callback_url))
    }

    pub async fn sync(
        &self,
        access_token: &str,
    ) -> Result<(
        String,
        String,
        HashMap<String, String>,
        Vec<crate::db::Entry<Encrypted>>,
    )> {
        let res = ClientRequest::Sync(access_token)
            .req(self)
            .await?
            .error_for_status()?;

        let sync_res: SyncRes = res.json_with_path().await?;

        let ciphers = sync_res
            .ciphers
            .into_iter()
            .filter_map(|cipher| cipher.to_entry(&sync_res.folders))
            .collect();

        let org_keys = sync_res
            .profile
            .organizations
            .iter()
            .map(|org| (org.id.clone(), org.key.clone()))
            .collect();

        Ok((
            sync_res.profile.key,
            sync_res.profile.private_key,
            org_keys,
            ciphers,
        ))
    }

    pub fn add(
        &self,
        access_token: &str,
        name: &str,
        data: &EntryData,
        notes: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<()> {
        let req = CiphersPostReq {
            folder_id: folder_id.map(ToString::to_string),
            name: name.to_string(),
            notes: notes.map(ToString::to_string),
            data: EntryDataWire(data),
        };

        ClientBlockingRequest::Add(access_token, req)
            .req(self)?
            .error_for_status()?;

        Ok(())
    }

    pub fn edit(&self, access_token: &str, entry: &crate::db::Entry<Encrypted>) -> Result<()> {
        let req = CiphersPutReq {
            folder_id: entry.folder_id.clone(),
            organization_id: entry.org_id.clone(),
            name: entry.name.clone(),
            notes: entry.notes.clone(),
            data: EntryDataWire(&entry.data),
            fields: entry
                .fields
                .iter()
                .map(|field| CipherDynamicField {
                    ty: field.ty,
                    name: field.name.clone(),
                    value: field.value.clone(),
                    linked_id: field.linked_id,
                })
                .collect(),
            password_history: entry
                .history
                .iter()
                .map(|entry| CiphersPutReqHistory {
                    last_used_date: entry.last_used_date.clone(),
                    password: entry.password.clone(),
                })
                .collect(),
        };

        ClientBlockingRequest::Edit(access_token, &entry.id, req)
            .req(self)?
            .error_for_status()?;

        Ok(())
    }

    pub fn remove(&self, access_token: &str, id: &str) -> Result<()> {
        ClientBlockingRequest::Remove(access_token, id)
            .req(self)?
            .error_for_status()?;

        Ok(())
    }

    pub fn folders(&self, access_token: &str) -> Result<Vec<(String, String)>> {
        let res = ClientBlockingRequest::Folders(access_token)
            .req(self)?
            .error_for_status()?;

        let folders_res: FoldersRes = res.json_with_path()?;

        Ok(folders_res
            .data
            .iter()
            .map(|folder| (folder.id.clone(), folder.name.clone()))
            .collect())
    }

    pub fn create_folder(&self, access_token: &str, name: &str) -> Result<String> {
        let res = ClientBlockingRequest::CreateFolder(access_token, name)
            .req(self)?
            .error_for_status()?;

        let folders_res: FoldersResData = res.json_with_path()?;

        Ok(folders_res.id)
    }

    pub fn exchange_refresh_token(&self, refresh_token: &str) -> Result<String> {
        let res = ClientBlockingRequest::ExchangeRefreshToken(refresh_token).req(self)?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path()?;
        Ok(connect_res.access_token)
    }

    pub async fn exchange_refresh_token_async(&self, refresh_token: &str) -> Result<String> {
        let res = ClientRequest::ExchangeRefreshToken(refresh_token)
            .req(self)
            .await?;
        let connect_res: ConnectRefreshTokenRes = res.json_with_path().await?;
        Ok(connect_res.access_token)
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn identity_url(&self, path: &str) -> String {
        format!("{}{}", self.identity_url, path)
    }
}

async fn find_free_port(bottom: u16, top: u16) -> Result<u16> {
    for port in bottom..top {
        if tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(port);
        }
    }

    Err(Error::FailedToFindFreePort {
        range: format!("({bottom}..{top})"),
    })
}

#[derive(Clone)]
struct SSOHandlerState {
    state: String,
    sender: mpsc::Sender<Result<String>>,
}

async fn start_sso_callback_server(
    listener: tokio::net::TcpListener,
    state: &str,
) -> Result<String> {
    let (shut_tx, mut shut_rx) = mpsc::channel(1);
    let (tx, mut rx) = mpsc::channel(1);

    let sso_handler_state = Arc::new(SSOHandlerState {
        state: state.to_string(),
        sender: shut_tx,
    });

    let app = axum::Router::new()
        .route("/", axum::routing::get(handle_sso_callback))
        .with_state(sso_handler_state);

    axum::serve(listener, app)
        .with_graceful_shutdown(
            async move { tx.send(shut_rx.recv().await.unwrap()).await.unwrap() },
        )
        .await
        .map_err(|e| Error::FailedToProcessSSOCallback { msg: e.to_string() })?;

    rx.recv().await.unwrap()
}

async fn handle_sso_callback(
    axum::extract::State(state): axum::extract::State<Arc<SSOHandlerState>>,
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
) -> axum::http::Response<String> {
    match sso_query_code(&params, state.state.as_str()) {
        Ok(sso_code) => {
            state.sender.send(Ok(sso_code)).await.unwrap();

            axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .body(
                    "<html><head><title>Success | rbw</title></head><body> \
                  <h1>Successfully authenticated with rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>"
                        .to_string(),
                )
                .unwrap()
        }
        Err(e) => {
            state.sender.send(Err(e)).await.unwrap();

            axum::http::Response::builder()
                .status(axum::http::StatusCode::BAD_REQUEST)
                .body(
                    "<html><head><title>Failed | rbw</title></head><body> \
                  <h1>Something went wrong logging into the rbw</h1> \
                  <p>You may now close this tab and return to the terminal.</p> \
                  </body></html>"
                        .to_string(),
                )
                .unwrap()
        }
    }
}

fn sso_query_code(params: &HashMap<String, String>, state: &str) -> Result<String> {
    let sso_code = params
        .get("code")
        .ok_or(Error::FailedToProcessSSOCallback {
            msg: "Could not obtain code from the URL".to_string(),
        })?;

    let received_state = params
        .get("state")
        .ok_or(Error::FailedToProcessSSOCallback {
            msg: "Could not obtain state from the URL".to_string(),
        })?;

    if received_state.split("_identifier=").next().unwrap() != state {
        return Err(Error::FailedToProcessSSOCallback {
            msg: format!(
                "SSO callback states do not match, sent: {state}, received: {received_state}"
            ),
        });
    }

    Ok(sso_code.clone())
}
