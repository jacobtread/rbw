use crate::prelude::*;

use std::{
    fmt::Display,
    io::{Read as _, Write as _},
    str::FromStr,
};

use anyhow::Context as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
}

impl FromStr for FieldType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
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
            _ => anyhow::bail!("unknown field {s}"),
        })
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
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Field {
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

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct Entry {
    pub id: String,
    pub org_id: Option<String>,
    pub folder: Option<String>,
    pub folder_id: Option<String>,
    pub name: String,
    pub data: EntryData,
    pub fields: Vec<Field>,
    pub notes: Option<String>,
    pub history: Vec<HistoryEntry>,
    pub key: Option<String>,
    pub master_password_reprompt: crate::api::CipherRepromptType,
}

impl Entry {
    pub fn master_password_reprompt(&self) -> bool {
        self.master_password_reprompt != crate::api::CipherRepromptType::None
    }

    fn get_short(&self) -> Option<String> {
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

    pub fn display_short(
        &self,
        desc: &str,
        clipboard: bool,
        val_display_or_store: fn(bool, &str) -> bool,
    ) -> bool {
        let short = self.get_short();
        let Some(short) = short else {
            // Would be cool if self.data had a method named main_field_name :D
            eprintln!(
                "entry for '{desc}' had no {}",
                match &self.data {
                    EntryData::Login { .. } => "password",
                    EntryData::Card { .. } => "card number",
                    EntryData::Identity { .. } => "name",
                    EntryData::SecureNote => "notes",
                    EntryData::SshKey { .. } => "public key",
                }
            );
            return false;
        };

        val_display_or_store(clipboard, &short)
    }

    /// This function is sh*t but I need it for now
    fn get_fields(
        &self,
        field: &str,
        generate_totp: fn(&str) -> anyhow::Result<String>,
    ) -> Vec<String> {
        let ret: Vec<Option<String>> = match &self.data {
            EntryData::Login {
                username,
                totp,
                uris,
                ..
            } => match field.parse() {
                Ok(FieldType::Notes) => vec![self.notes.clone()],
                Ok(FieldType::Username) => vec![username.clone()],

                Ok(FieldType::Totp) => {
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
                Ok(FieldType::Uris) => {
                    if !uris.is_empty() {
                        let uri_strs: Vec<_> = uris.iter().map(|uri| uri.uri.clone()).collect();
                        // val_display_or_store(clipboard, &uri_strs.join("\n"));
                        vec![Some(uri_strs.join("\n"))]
                    } else {
                        vec![]
                    }
                }
                Ok(FieldType::Password) => {
                    // self.display_short(desc, clipboard);
                    vec![self.get_short()]
                }
                _ => {
                    self.fields
                        .iter()
                        .map(|f| {
                            if let Some(name) = &f.name {
                                if name.to_lowercase().contains(field) {
                                    f.value.clone()
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        })
                        .collect()

                    // for f in &self.fields {
                    //     if let Some(name) = &f.name {
                    //         if name.to_lowercase().as_str().contains(field) {
                    //             val_display_or_store(clipboard, f.value.as_deref().unwrap_or(""));
                    //             break;
                    //         }
                    //     }
                    // }
                }
            },
            EntryData::Card {
                cardholder_name,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => match field.parse() {
                Ok(FieldType::CardNumber) => vec![self.get_short()],
                Ok(FieldType::Expiration) => {
                    if let (Some(month), Some(year)) = (exp_month, exp_year) {
                        vec![Some(format!("{month}/{year}"))]
                        //val_display_or_store(clipboard, &format!("{month}/{year}"));
                    } else {
                        vec![]
                    }
                }
                Ok(FieldType::ExpMonth) => vec![exp_month.clone()],
                Ok(FieldType::ExpYear) => vec![exp_year.clone()],
                Ok(FieldType::Cvv) => vec![code.clone()],
                Ok(FieldType::Name | FieldType::Cardholder) => vec![cardholder_name.clone()],
                Ok(FieldType::Brand) => vec![brand.clone()],
                Ok(FieldType::Notes) => vec![self.notes.clone()],
                _ => self
                    .fields
                    .iter()
                    .map(|f| {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().contains(field) {
                                f.value.clone()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect(),
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
            } => match field.parse() {
                Ok(FieldType::Name) => vec![self.get_short()],
                Ok(FieldType::Email) => vec![email.clone()],
                Ok(FieldType::Address) => {
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
                Ok(FieldType::City) => vec![city.clone()],
                Ok(FieldType::State) => vec![state.clone()],
                Ok(FieldType::PostalCode) => vec![postal_code.clone()],
                Ok(FieldType::Country) => vec![country.clone()],
                Ok(FieldType::Phone) => vec![phone.clone()],
                Ok(FieldType::Ssn) => vec![ssn.clone()],
                Ok(FieldType::License) => vec![license_number.clone()],
                Ok(FieldType::Passport) => vec![passport_number.clone()],
                Ok(FieldType::Username) => vec![username.clone()],
                Ok(FieldType::Notes) => vec![self.notes.clone()],
                _ => self
                    .fields
                    .iter()
                    .map(|f| {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().contains(field) {
                                f.value.clone()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect(),
            },

            EntryData::SecureNote => match field.parse() {
                Ok(FieldType::Notes) => vec![self.get_short()],
                _ => self
                    .fields
                    .iter()
                    .map(|f| {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().contains(field) {
                                f.value.clone()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect(),
            },

            EntryData::SshKey {
                fingerprint,
                private_key,
                ..
            } => match field.parse() {
                Ok(FieldType::Fingerprint) => vec![fingerprint.clone()],
                Ok(FieldType::PublicKey) => vec![self.get_short()],
                Ok(FieldType::PrivateKey) => vec![private_key.clone()],
                Ok(FieldType::Notes) => vec![self.notes.clone()],
                _ => self
                    .fields
                    .iter()
                    .map(|f| {
                        if let Some(name) = &f.name {
                            if name.to_lowercase().contains(field) {
                                f.value.clone()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect(),
            },
        };

        ret.into_iter().flatten().collect()
    }

    pub fn display_field(
        &self,
        desc: &str,
        field: &str,
        clipboard: bool,
        val_display_or_store: fn(bool, &str) -> bool,
        generate_totp: fn(&str) -> anyhow::Result<String>,
    ) {
        let fields = self.get_fields(&field.to_lowercase(), generate_totp);
        fields.iter().for_each(|f| {
            val_display_or_store(clipboard, f);
        });
    }

    pub fn display_long(
        &self,
        desc: &str,
        clipboard: bool,
        val_display_or_store: fn(bool, &str) -> bool,
        display_field: fn(&str, Option<&str>, bool) -> bool,
    ) {
        let mut displayed = self.display_short(desc, clipboard, val_display_or_store);
        match &self.data {
            EntryData::Login {
                username,
                totp,
                uris,
                ..
            } => {
                displayed |= display_field("Username", username.as_deref(), clipboard);
                displayed |= display_field("TOTP Secret", totp.as_deref(), clipboard);

                for uri in uris {
                    displayed |= display_field("URI", Some(&uri.uri), clipboard);
                    let match_type = uri.match_type.map(|ty| format!("{ty}"));
                    displayed |= display_field("Match type", match_type.as_deref(), clipboard);
                }

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
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
                if let (Some(exp_month), Some(exp_year)) = (exp_month, exp_year) {
                    println!("Expiration: {exp_month}/{exp_year}");
                    displayed = true;
                }
                displayed |= display_field("CVV", code.as_deref(), clipboard);
                displayed |= display_field("Name", cardholder_name.as_deref(), clipboard);
                displayed |= display_field("Brand", brand.as_deref(), clipboard);
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
                displayed |= display_field("Address", address1.as_deref(), clipboard);
                displayed |= display_field("Address", address2.as_deref(), clipboard);
                displayed |= display_field("Address", address3.as_deref(), clipboard);
                displayed |= display_field("City", city.as_deref(), clipboard);
                displayed |= display_field("State", state.as_deref(), clipboard);
                displayed |= display_field("Postcode", postal_code.as_deref(), clipboard);
                displayed |= display_field("Country", country.as_deref(), clipboard);
                displayed |= display_field("Phone", phone.as_deref(), clipboard);
                displayed |= display_field("Email", email.as_deref(), clipboard);
                displayed |= display_field("SSN", ssn.as_deref(), clipboard);
                displayed |= display_field("License", license_number.as_deref(), clipboard);
                displayed |= display_field("Passport", passport_number.as_deref(), clipboard);
                displayed |= display_field("Username", username.as_deref(), clipboard);
            }
            EntryData::SecureNote => {}
            EntryData::SshKey { fingerprint, .. } => {
                displayed |= display_field("Fingerprint", fingerprint.as_deref(), clipboard);

                for field in &self.fields {
                    displayed |= display_field(
                        field.name.as_deref().unwrap_or("(null)"),
                        Some(field.value.as_deref().unwrap_or("")),
                        clipboard,
                    );
                }
            }
        }

        if !matches!(&self.data, EntryData::SecureNote) {
            if let Some(notes) = &self.notes {
                if displayed {
                    println!();
                }
                println!("{notes}");
            }
        }
    }

    /// This implementation mirror the `fn display_fied` method on which field to list
    pub fn display_fields_list(&self) {
        match &self.data {
            EntryData::Login {
                username,
                password,
                totp,
                uris,
                ..
            } => {
                if username.is_some() {
                    println!("{}", FieldType::Username);
                }
                if totp.is_some() {
                    println!("{}", FieldType::Totp);
                }
                if !uris.is_empty() {
                    println!("{}", FieldType::Uris);
                }
                if password.is_some() {
                    println!("{}", FieldType::Password);
                }
            }
            EntryData::Card {
                cardholder_name,
                number,
                brand,
                exp_month,
                exp_year,
                code,
                ..
            } => {
                if number.is_some() {
                    println!("{}", FieldType::CardNumber);
                }
                if exp_month.is_some() {
                    println!("{}", FieldType::ExpMonth);
                }
                if exp_year.is_some() {
                    println!("{}", FieldType::ExpYear);
                }
                if code.is_some() {
                    println!("{}", FieldType::Cvv);
                }
                if cardholder_name.is_some() {
                    println!("{}", FieldType::Cardholder);
                }
                if brand.is_some() {
                    println!("{}", FieldType::Brand);
                }
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
                title,
                first_name,
                middle_name,
                last_name,
                ..
            } => {
                if [title, first_name, middle_name, last_name]
                    .iter()
                    .any(|f| f.is_some())
                {
                    // the display_field combines all these fields together.
                    println!("name");
                }
                if email.is_some() {
                    println!("{}", FieldType::Email);
                }
                if [address1, address2, address3].iter().any(|f| f.is_some()) {
                    // the display_field combines all these fields together.
                    println!("address");
                }
                if city.is_some() {
                    println!("{}", FieldType::City);
                }
                if state.is_some() {
                    println!("{}", FieldType::State);
                }
                if postal_code.is_some() {
                    println!("{}", FieldType::PostalCode);
                }
                if country.is_some() {
                    println!("{}", FieldType::Country);
                }
                if phone.is_some() {
                    println!("{}", FieldType::Phone);
                }
                if ssn.is_some() {
                    println!("{}", FieldType::Ssn);
                }
                if license_number.is_some() {
                    println!("{}", FieldType::License);
                }
                if passport_number.is_some() {
                    println!("{}", FieldType::Passport);
                }
                if username.is_some() {
                    println!("{}", FieldType::Username);
                }
            }

            EntryData::SecureNote => (), // handled at the end
            EntryData::SshKey {
                fingerprint,
                public_key,
                ..
            } => {
                if fingerprint.is_some() {
                    println!("{}", FieldType::Fingerprint);
                }
                if public_key.is_some() {
                    println!("{}", FieldType::PublicKey);
                }
            }
        }

        if self.notes.is_some() {
            println!("{}", FieldType::Notes);
        }
        for f in &self.fields {
            if let Some(name) = &f.name {
                println!("{name}");
            }
        }
    }

    pub fn display_json(&self, desc: &str) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(std::io::stdout(), &self)
            .context(format!("failed to write entry '{desc}' to stdout"))?;
        println!();

        Ok(())
    }
}

#[derive(serde::Serialize, Debug, Clone, Eq, PartialEq)]
pub struct Uri {
    pub uri: String,
    pub match_type: Option<crate::api::UriMatchType>,
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

    pub entries: Vec<Entry>,
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
