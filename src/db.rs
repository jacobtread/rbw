use crate::prelude::*;

use std::{
    fmt::Display,
    io::{Read as _, Write as _},
};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldType {
    Notes,
    Username,
    Password,
    Totp,
    Uris,
    IdentityName,
    City,
    State,
    PostalCode,
    Country,
    Phone,
    Ssn,
    License,
    Passport,
    CardNumber,
    Expiration,
    ExpMonth,
    ExpYear,
    Cvv,
    Cardholder,
    Brand,
    Name,
    Email,
    Address,
    Address1,
    Address2,
    Address3,
    Fingerprint,
    PublicKey,
    PrivateKey,
    Title,
    FirstName,
    MiddleName,
    LastName,
    Custom(String),
}

impl From<&str> for FieldType {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "notes" | "note" => Self::Notes,
            "username" | "user" => Self::Username,
            "password" => Self::Password,
            "totp" | "code" => Self::Totp,
            "uris" | "urls" | "sites" => Self::Uris,
            "identityname" => Self::IdentityName,
            "city" => Self::City,
            "state" => Self::State,
            "postcode" | "zipcode" | "zip" => Self::PostalCode,
            "country" => Self::Country,
            "phone" => Self::Phone,
            "ssn" => Self::Ssn,
            "license" => Self::License,
            "passport" => Self::Passport,
            "number" | "card" => Self::CardNumber,
            "exp" => Self::Expiration,
            "exp_month" | "month" => Self::ExpMonth,
            "exp_year" | "year" => Self::ExpYear,
            // the word "code" got preceeded by Totp
            "cvv" => Self::Cvv,
            "cardholder" | "cardholder_name" => Self::Cardholder,
            "brand" | "type" => Self::Brand,
            "name" => Self::Name,
            "email" => Self::Email,
            "address1" => Self::Address1,
            "address2" => Self::Address2,
            "address3" => Self::Address3,
            "address" => Self::Address,
            "fingerprint" => Self::Fingerprint,
            "public_key" => Self::PublicKey,
            "private_key" => Self::PrivateKey,
            "title" => Self::Title,
            "first_name" => Self::FirstName,
            "middle_name" => Self::MiddleName,
            "last_name" => Self::LastName,
            _ => Self::Custom(s.to_string()),
        }
    }
}

impl Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Notes => "notes",
            Self::Username => "username",
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Uris => "uris",
            Self::IdentityName => "identityname",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postcode",
            Self::Country => "country",
            Self::Phone => "phone",
            Self::Ssn => "ssn",
            Self::License => "license",
            Self::Passport => "passport",
            Self::CardNumber => "number",
            Self::Expiration => "exp",
            Self::ExpMonth => "exp_month",
            Self::ExpYear => "exp_year",
            Self::Cvv => "cvv",
            Self::Cardholder => "cardholder",
            Self::Brand => "brand",
            Self::Name => "name",
            Self::Email => "email",
            Self::Address1 => "address1",
            Self::Address2 => "address2",
            Self::Address3 => "address3",
            Self::Address => "address",
            Self::Fingerprint => "fingerprint",
            Self::PublicKey => "public_key",
            Self::PrivateKey => "private_key",
            Self::Title => "title",
            Self::FirstName => "first_name",
            Self::MiddleName => "middle_name",
            Self::LastName => "last_name",
            Self::Custom(name) => name,
        })
    }
}

/// Used to describe custom fields in the application.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct DynamicField {
    pub ty: Option<crate::api::FieldType>,
    pub name: Option<String>,
    pub value: Option<String>,
    pub linked_id: Option<crate::api::LinkedIdType>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum EntryData {
    Login {
        username: Option<String>,
        password: Option<String>,
        totp: Option<String>,
        uris: Vec<Uri>,
    },
    Card {
        cardholder_name: Option<String>,
        number: Option<String>,
        brand: Option<String>,
        exp_month: Option<String>,
        exp_year: Option<String>,
        code: Option<String>,
    },
    Identity {
        title: Option<String>,
        first_name: Option<String>,
        middle_name: Option<String>,
        last_name: Option<String>,
        address1: Option<String>,
        address2: Option<String>,
        address3: Option<String>,
        city: Option<String>,
        state: Option<String>,
        postal_code: Option<String>,
        country: Option<String>,
        phone: Option<String>,
        email: Option<String>,
        ssn: Option<String>,
        license_number: Option<String>,
        passport_number: Option<String>,
        username: Option<String>,
    },
    SecureNote,
    SshKey {
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
    },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct HistoryEntry {
    pub last_used_date: String,
    pub password: String,
}

// These are markers for type state pattern
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Encrypted;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Decrypted;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Entry<State> {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<DynamicField>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
    #[serde(skip)]
    pub _state: std::marker::PhantomData<State>,
}

// Most impl fn don't belong here. I am talking of display ones, but looking to relocate them
// later in the refactor process.
impl<T> Entry<T> {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }
}

impl Entry<Decrypted> {
    /// The "short" is the first field that comes to mind when speaking of a entry, like the
    /// password for the Login , the number for the Card, etc.
    pub fn get_short(&self) -> Option<String> {
        match &self.data {
            EntryData::Login { password, .. } => password.clone(),
            EntryData::Card { number, .. } => number.clone(),
            EntryData::Identity {
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                let names: Vec<String> = [title, first_name, middle_name, last_name]
                    .iter()
                    .copied()
                    .flatten()
                    .cloned()
                    .collect();

                if names.is_empty() {
                    None
                } else {
                    Some(names.join(" "))
                }
            }
            EntryData::SecureNote => self.notes.clone(),
            EntryData::SshKey { public_key, .. } => public_key.clone(),
        }
    }

    /// Get all the custom fields defined by the user with the same name. Yes there can be more
    /// than one custom field with the same name. Don't ask me why.
    fn get_dynamic_fields(&self, name: &str) -> Vec<Option<String>> {
        self.fields
            .iter()
            .map(|f| {
                if let Some(fname) = &f.name {
                    if fname.to_lowercase().contains(name) {
                        f.value.clone()
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// This function is sh*t but I need it for now
    /// Given a textual representation of a field, like "username", "password" or "card number",
    /// check which type of entry EntryData is and extract the "username" or "cardnumber" field if
    /// available from the "static" fields, else go check for the dynamic ones.
    /// For example, if the EntryData is of type EntryData::Login, try to extract the username from the
    /// static username field, but if the field param is not within the static fields, search for it through the dynamic ones.
    /// The dynamic fields are the user's added ones and labeled as "Custom field" in GUI apps.
    pub fn get_field(
        &self,
        field: &str,
        generate_totp: fn(&str) -> anyhow::Result<String>,
    ) -> Vec<String> {
        let ftype: FieldType = field.into();
        let ret: Vec<Option<String>> = match &self.data {
            EntryData::Login {
                username,
                totp,
                uris,
                ..
            } => match &ftype {
                FieldType::Notes => vec![self.notes.clone()],
                FieldType::Username => vec![username.clone()],
                FieldType::Totp => {
                    if let Some(totp) = totp {
                        match generate_totp(totp) {
                            Ok(code) => {
                                vec![Some(code)]

                                // val_display_or_store(clipboard, &code);
                            }
                            Err(e) => {
                                eprintln!("{e}");
                                vec![]
                            }
                        }
                    } else {
                        vec![]
                    }
                }
                FieldType::Uris => {
                    if !uris.is_empty() {
                        let uri_strs: Vec<_> = uris.iter().map(|uri| uri.uri.clone()).collect();
                        // val_display_or_store(clipboard, &uri_strs.join("\n"));
                        vec![Some(uri_strs.join("\n"))]
                    } else {
                        vec![]
                    }
                }
                FieldType::Password => {
                    // self.display_short(desc, clipboard);
                    vec![self.get_short()]
                }
                // This should be Custom
                _ => self.get_dynamic_fields(field),
            },
            EntryData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match &ftype {
                FieldType::CardNumber => vec![self.get_short()],
                FieldType::Expiration => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        vec![Some(format!("{month}/{year}"))]
                        //val_display_or_store(clipboard, &format!("{month}/{year}"));
                    } else {
                        vec![]
                    }
                }
                FieldType::ExpMonth => vec![exp_month.clone()],
                FieldType::ExpYear => vec![exp_year.clone()],
                FieldType::Cvv => vec![code.clone()],
                FieldType::Name | FieldType::Cardholder => vec![cardholder_name.clone()],
                FieldType::Brand => vec![brand.clone()],
                FieldType::Notes => vec![self.notes.clone()],
                // This should be Custom
                _ => self.get_dynamic_fields(field),
            },
            EntryData::Identity {
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
                ..
            } => match &ftype {
                FieldType::Name => vec![self.get_short()],
                FieldType::Email => vec![email.clone()],
                FieldType::Address => {
                    let mut strs = vec![];

                    if let Some(address1) = address1 {
                        strs.push(address1.clone());
                    }
                    if let Some(address2) = address2 {
                        strs.push(address2.clone());
                    }
                    if let Some(address3) = address3 {
                        strs.push(address3.clone());
                    }

                    if !strs.is_empty() {
                        vec![Some(strs.join("\n"))]
                        //val_display_or_store(clipboard, &strs.join("\n"));
                    } else {
                        vec![]
                    }
                }
                FieldType::City => vec![city.clone()],
                FieldType::State => vec![state.clone()],
                FieldType::PostalCode => vec![postal_code.clone()],
                FieldType::Country => vec![country.clone()],
                FieldType::Phone => vec![phone.clone()],
                FieldType::Ssn => vec![ssn.clone()],
                FieldType::License => vec![license_number.clone()],
                FieldType::Passport => vec![passport_number.clone()],
                FieldType::Username => vec![username.clone()],
                FieldType::Notes => vec![self.notes.clone()],
                _ => self.get_dynamic_fields(field),
            },

            EntryData::SecureNote => match &ftype {
                FieldType::Notes => vec![self.get_short()],
                _ => self.get_dynamic_fields(field),
            },

            EntryData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match &ftype {
                FieldType::Fingerprint => vec![fingerprint.clone()],
                FieldType::PublicKey => vec![self.get_short()],
                FieldType::PrivateKey => vec![private_key.clone()],
                FieldType::Notes => vec![self.notes.clone()],
                _ => self.get_dynamic_fields(field),
            },
        };

        ret.into_iter().flatten().collect()
    }
}

pub trait Decrypter {
    fn decrypt_field(&mut self, entry: &Entry<Encrypted>, field: &str) -> anyhow::Result<String>;
}

impl Entry<Encrypted> {
    fn decrypt_optstring(
        &self,
        optstring: &Option<String>,
        decrypter: &mut impl Decrypter,
    ) -> anyhow::Result<Option<String>> {
        Ok(match optstring {
            Some(s) => Some(decrypter.decrypt_field(&self, s)?),
            None => None,
        })
    }

    pub fn decrypt_custom_fields(
        &self,
        decrypter: &mut impl Decrypter,
    ) -> anyhow::Result<Vec<DynamicField>> {
        self.fields
            .iter()
            .map(|field| {
                Ok(DynamicField {
                    name: self.decrypt_optstring(&field.name, decrypter)?,
                    value: self.decrypt_optstring(&field.value, decrypter)?,
                    ty: field.ty,
                    linked_id: None, // TODO: Check if None here is correct
                })
            })
            .collect()
    }

    pub fn decrypt(&self, decrypter: &mut impl Decrypter) -> anyhow::Result<Entry<Decrypted>> {
        // folder name should always be decrypted with the local key because
        // folders are local to a specific user's vault, not the organization
        let folder = self.decrypt_optstring(&self.folder, decrypter)?;

        let fields = self.decrypt_custom_fields(decrypter)?;

        let notes = self.decrypt_optstring(&self.notes, decrypter)?;

        let history = self
            .history
            .iter()
            .map(|he| {
                Ok(HistoryEntry {
                    last_used_date: he.last_used_date.clone(),
                    password: decrypter.decrypt_field(&self, &he.password)?,
                })
            })
            .collect::<anyhow::Result<_>>()?;

        let mut df = |_ft, val: &Option<String>| self.decrypt_optstring(&val, decrypter);

        let data = match &self.data {
            EntryData::Login {
                username,
                password,
                totp,
                uris,
            } => EntryData::Login {
                username: df(FieldType::Username, username)?,
                password: df(FieldType::Password, password)?,
                totp: df(FieldType::Totp, totp)?,
                uris: uris
                    .iter()
                    .map(|s| {
                        Ok(df(FieldType::Uris, &Some(s.uri.clone()))?.map(|uri| Uri {
                            uri,
                            match_type: s.match_type,
                        }))
                    })
                    .collect::<anyhow::Result<Vec<Option<Uri>>>>()?
                    .into_iter()
                    .flatten()
                    .collect(),
            },
            EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
            } => EntryData::Card {
                cardholder_name: df(FieldType::Cardholder, cardholder_name)?,
                number: df(FieldType::CardNumber, number)?,
                brand: df(FieldType::Brand, brand)?,
                exp_month: df(FieldType::ExpMonth, exp_month)?,
                exp_year: df(FieldType::ExpYear, exp_year)?,
                code: df(FieldType::Cvv, code)?,
            },
            EntryData::Identity {
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
            } => EntryData::Identity {
                title: df(FieldType::Title, title)?,
                first_name: df(FieldType::FirstName, first_name)?,
                middle_name: df(FieldType::MiddleName, middle_name)?,
                last_name: df(FieldType::LastName, last_name)?,
                address1: df(FieldType::Address1, address1)?,
                address2: df(FieldType::Address2, address2)?,
                address3: df(FieldType::Address3, address3)?,
                city: df(FieldType::City, city)?,
                state: df(FieldType::State, state)?,
                postal_code: df(FieldType::PostalCode, postal_code)?,
                country: df(FieldType::Country, country)?,
                phone: df(FieldType::Phone, phone)?,
                email: df(FieldType::Email, email)?,
                ssn: df(FieldType::Ssn, ssn)?,
                license_number: df(FieldType::License, license_number)?,
                passport_number: df(FieldType::Passport, passport_number)?,
                username: df(FieldType::Username, username)?,
            },
            EntryData::SecureNote => EntryData::SecureNote {},
            EntryData::SshKey {
                public_key,
                fingerprint,
                private_key,
            } => EntryData::SshKey {
                public_key: df(FieldType::PublicKey, public_key)?,
                fingerprint: df(FieldType::Fingerprint, fingerprint)?,
                private_key: df(FieldType::PrivateKey, private_key)?,
            },
        };

        Ok(Entry::<Decrypted> {
            id: self.id.clone(),
            folder,
            folder_id: None,
            org_id: None,
            key: None,
            name: decrypter.decrypt_field(&self, &self.name)?,
            data,
            fields,
            notes,
            history,
            master_password_reprompt: crate::api::CipherRepromptType::None,
            _state: std::marker::PhantomData,
        })
    }
}

fn writefield(
    f: &mut std::fmt::Formatter<'_>,
    label: &str,
    field: &Option<String>,
    displayed: &mut bool,
) -> std::fmt::Result {
    if let Some(field) = field {
        *displayed = true;
        writeln!(f, "{label}: {field}")
    } else {
        Ok(())
    }
}

/// Display impl is a bit messy as we need to support previous output format.
/// I would, for example, yank this displayed bool and always print Notes after ---.
/// I would avoid printing the "short" field this way too, but rather print it as a normal field.
impl Display for Entry<Decrypted> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(short) = self.get_short() {
            writeln!(f, "{short}")?;
        }

        let mut d = false;

        match &self.data {
            EntryData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                writefield(f, "Username", username, &mut d)?;
                writefield(f, "TOTP Secret", totp, &mut d)?;

                for uri in uris {
                    d = true;
                    write!(f, "{uri}")?;
                }

                for field in &self.fields {
                    d = true;
                    writeln!(
                        f,
                        "{}: {}",
                        field.name.as_deref().unwrap_or("(null)"),
                        field.value.as_deref().unwrap_or("")
                    )?;
                }
            }
            EntryData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if let (Some(m), Some(y)) = (exp_month, exp_year) {
                    writefield(f, "Expiration", &Some(format!("{m}/{y}")), &mut d)?;
                }

                writefield(f, "CVV", code, &mut d)?;
                writefield(f, "Name", cardholder_name, &mut d)?;
                writefield(f, "Brand", brand, &mut d)?;
            }
            EntryData::Identity {
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
                ..
            } => {
                writefield(f, "Address", address1, &mut d)?;
                writefield(f, "Address", address2, &mut d)?;
                writefield(f, "Address", address3, &mut d)?;
                writefield(f, "City", city, &mut d)?;
                writefield(f, "State", state, &mut d)?;
                writefield(f, "Postcode", postal_code, &mut d)?;
                writefield(f, "Country", country, &mut d)?;
                writefield(f, "Phone", phone, &mut d)?;
                writefield(f, "Email", email, &mut d)?;
                writefield(f, "SSN", ssn, &mut d)?;
                writefield(f, "License", license_number, &mut d)?;
                writefield(f, "Passport", passport_number, &mut d)?;
                writefield(f, "Username", username, &mut d)?;
            }
            EntryData::SecureNote => {}
            EntryData::SshKey { fingerprint, .. } => {
                writefield(f, "Fingerprint", fingerprint, &mut d)?;

                for field in &self.fields {
                    d = true;
                    writeln!(
                        f,
                        "{}: {}",
                        field.name.as_deref().unwrap_or("(null)"),
                        field.value.as_deref().unwrap_or("")
                    )?;
                }
            }
        }

        if !matches!(self.data, EntryData::SecureNote) {
            if let Some(notes) = &self.notes {
                if d {
                    println!();
                }
                println!("{notes}");
            }
        }

        Ok(())
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
}

impl Display for Uri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "URI: {}", &self.uri)?;

        if let Some(ty) = self.match_type {
            writeln!(f, "Match type: {ty}")?;
        }

        Ok(())
    }
}

// backwards compatibility
impl<'de> serde::Deserialize<'de> for Uri {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrUri;
        impl<'de> serde::de::Visitor<'de> for StringOrUri {
            type Value = Uri;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("uri")
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(Uri {
                    uri: value.to_string(),
                    match_type: None,
                })
            }

            fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let mut uri = None;
                let mut match_type = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        "uri" => {
                            if uri.is_some() {
                                return Err(serde::de::Error::duplicate_field("uri"));
                            }
                            uri = Some(map.next_value()?);
                        }
                        "match_type" => {
                            if match_type.is_some() {
                                return Err(serde::de::Error::duplicate_field("match_type"));
                            }
                            match_type = map.next_value()?;
                        }
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                key,
                                &["uri", "match_type"],
                            ))
                        }
                    }
                }

                uri.map_or_else(
                    || Err(serde::de::Error::missing_field("uri")),
                    |uri| Ok(Self::Value { uri, match_type }),
                )
            }
        }

        deserializer.deserialize_any(StringOrUri)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Default, Debug)]
pub struct Db {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,

    pub kdf: Option<crate::api::KdfType>,
    pub iterations: Option<u32>,
    pub memory: Option<u32>,
    pub parallelism: Option<u32>,
    pub protected_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_org_keys: std::collections::HashMap<String, String>,

    pub entries: Vec<Entry<Encrypted>>,
}

impl Db {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh = std::fs::File::open(&file).map_err(|source| Error::LoadDb {
            source,
            file: file.clone(),
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadDb {
                source,
                file: file.clone(),
            })?;
        let slf: Self =
            serde_json::from_str(&json).map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    pub async fn load_async(server: &str, email: &str) -> Result<Self> {
        let file = crate::dirs::db_file(server, email);
        let mut fh = tokio::fs::File::open(&file)
            .await
            .map_err(|source| Error::LoadDbAsync {
                source,
                file: file.clone(),
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .await
            .map_err(|source| Error::LoadDbAsync {
                source,
                file: file.clone(),
            })?;
        let slf: Self =
            serde_json::from_str(&json).map_err(|source| Error::LoadDbJson { source, file })?;
        Ok(slf)
    }

    // XXX need to make this atomic
    pub fn save(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(|source| Error::SaveDb {
            source,
            file: file.clone(),
        })?;
        let mut fh = std::fs::File::create(&file).map_err(|source| Error::SaveDb {
            source,
            file: file.clone(),
        })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveDbJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveDb { source, file })?;
        Ok(())
    }

    // XXX need to make this atomic
    pub async fn save_async(&self, server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        tokio::fs::create_dir_all(file.parent().unwrap())
            .await
            .map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        let mut fh = tokio::fs::File::create(&file)
            .await
            .map_err(|source| Error::SaveDbAsync {
                source,
                file: file.clone(),
            })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveDbJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .await
        .map_err(|source| Error::SaveDbAsync { source, file })?;
        Ok(())
    }

    pub fn remove(server: &str, email: &str) -> Result<()> {
        let file = crate::dirs::db_file(server, email);
        let res = std::fs::remove_file(&file);
        if let Err(e) = &res {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Ok(());
            }
        }
        res.map_err(|source| Error::RemoveDb { source, file })?;
        Ok(())
    }

    pub fn needs_login(&self) -> bool {
        self.access_token.is_none()
            || self.refresh_token.is_none()
            || self.iterations.is_none()
            || self.kdf.is_none()
            || self.protected_key.is_none()
    }
}
