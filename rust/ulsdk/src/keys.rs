// Copyright (c), CommunityLogiq Software

use serde_derive::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::Error;
use crate::Region;

#[derive(Deserialize, Clone)]
struct DiskKey {
    user_id: Uuid,
    region: Region,
    access_key: String,
    secret_key: String,
}

#[derive(Clone)]
pub struct Key {
    user_id: Uuid,
    region: Region,
    access_key: String,
    secret_key: Vec<u8>,
}

impl Key {
    pub fn try_new(
        user_id: Uuid,
        region: Region,
        access_key: String,
        secret_key: String,
    ) -> Result<Self, Error> {
        let secret_key = format!("{}==", secret_key);

        Ok(Key {
            user_id,
            region,
            access_key,
            secret_key: base64::decode(secret_key).map_err(|e| Error::from(e.to_string()))?,
        })
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn region(&self) -> Region {
        self.region
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }
}

pub fn load_key(profile: &str) -> Result<Key, Error> {
    let mut key_path = {
        let mut ul_dir = dirs::home_dir().unwrap();
        ul_dir.push(".ul");
        ul_dir
    };
    key_path.push("keys");

    let keys = std::fs::read_to_string(&key_path).map_err(|e| {
        Error::Unclassified(format!("Cannot read key file {:?}: {}", key_path, e).into())
    })?;
    let key_content: HashMap<String, DiskKey> =
        serde_ini::from_str(&keys).map_err(|e| Error::from(e.to_string()))?;

    let key = key_content
        .get(profile)
        .cloned()
        .ok_or_else(|| Error::from(format!("No key present for profile '{}'", profile)))?;

    let secret_key = format!("{}==", key.secret_key);
    Ok(Key {
        user_id: key.user_id,
        access_key: key.access_key,
        region: key.region,
        secret_key: base64::decode(secret_key).map_err(|e| Error::from(e.to_string()))?,
    })
}
