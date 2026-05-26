// serde_repr generates some as conversions that we can't seem to silence from
// here, unfortunately
#![allow(clippy::as_conversions)]

use std::{fmt::Display, str::FromStr};

use crate::{
    db::{Encrypted, EntryData},
    prelude::*,
};

use serde::{Deserialize, Serialize};

pub mod client;

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
struct CipherHistoryEntry {
    #[serde(rename = "LastUsedDate", alias = "lastUsedDate")]
    last_used_date: String,
    #[serde(rename = "Password", alias = "password")]
    password: Option<String>,
}

impl From<crate::db::HistoryEntry> for CipherHistoryEntry {
    fn from(value: crate::db::HistoryEntry) -> Self {
        Self {
            last_used_date: value.last_used_date,
            password: Some(value.password),
        }
    }
}

impl From<CipherHistoryEntry> for Option<crate::db::HistoryEntry> {
    fn from(value: CipherHistoryEntry) -> Self {
        let Some(password) = value.password else {
            return None;
        };

        Some(crate::db::HistoryEntry {
            last_used_date: value.last_used_date,
            password,
        })
    }
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
    password_history: Option<Vec<CipherHistoryEntry>>,
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
    fn into_entry(self, folders: &[SyncResFolder]) -> Option<crate::db::Entry<Encrypted>> {
        if self.deleted_date.is_some() {
            return None;
        }

        let history: Vec<crate::db::HistoryEntry> = self
            .password_history
            .map_or(vec![], |e| e.into_iter().filter_map(Into::into).collect());

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
            fields.into_iter().map(Into::into).collect()
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
    folder_id: Option<&'a str>,
    name: &'a str,
    notes: Option<&'a str>,
    #[serde(flatten)]
    data: EntryDataWire<'a>, // use lifetime parameter on the struct instead
}

#[derive(Serialize, Debug)]
struct CiphersPutReq<'a> {
    #[serde(rename = "folderId")]
    folder_id: Option<&'a str>,
    #[serde(rename = "organizationId")]
    organization_id: Option<&'a str>,
    name: &'a str,
    notes: Option<&'a str>,
    #[serde(flatten)]
    data: EntryDataWire<'a>,
    fields: &'a [CipherDynamicField],
    #[serde(rename = "passwordHistory")]
    password_history: &'a [CipherHistoryEntry],
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
