// Copyright (c), CommunityLogiq Software

use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Unclassified(Box<dyn std::error::Error>),
    #[cfg(not(target_arch = "wasm32"))]
    IoError(std::io::Error),
    #[cfg(not(target_arch = "wasm32"))]
    Reqwest(reqwest::Error),
    #[cfg(not(target_arch = "wasm32"))]
    FailedRequest(String, String, reqwest::StatusCode, String),
    SerdeJson(serde_json::error::Error),
    Serde(String),
    #[cfg(not(target_arch = "wasm32"))]
    Arrow(arrow::error::ArrowError),
    InvalidFlatbuffer(flatbuffers::InvalidFlatbuffer),
    InvalidId(String),
    InvalidEnumValue(i64),
}

// TODO: Blech.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for Error {}
unsafe impl Sync for Error {}
impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Error::Unclassified(err) => write!(f, "{}", err),
            #[cfg(not(target_arch = "wasm32"))]
            Error::IoError(err) => write!(f, "I/O Error: {}", err),
            #[cfg(not(target_arch = "wasm32"))]
            Error::Reqwest(err) => write!(f, "API error: {}", err),
            #[cfg(not(target_arch = "wasm32"))]
            Error::FailedRequest(endpoint, err, status, body) => write!(
                f,
                "Failed request to {}: {} ({}) Body: {}",
                endpoint, err, status, body
            ),
            Error::SerdeJson(err) => {
                write!(f, "Json deserialization error: {}", err)
            }
            Error::Serde(err) => {
                write!(f, "Serde error: {}", err)
            }
            #[cfg(not(target_arch = "wasm32"))]
            Error::Arrow(err) => write!(f, "Arrow Error: {}", err),
            Error::InvalidFlatbuffer(err) => write!(f, "Invalid Flatbuffer Error: {}", err),
            Error::InvalidId(err) => write!(f, "Invalid ID format: {}", err),
            Error::InvalidEnumValue(v) => write!(f, "Cannot convert value to enumeration: {}", v),
        }
    }
}

impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: core::fmt::Display,
    {
        let msg = format!("{}", msg);
        Self::Serde(msg)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Unclassified(e.into())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        Error::Reqwest(error)
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(e: serde_json::error::Error) -> Self {
        Error::SerdeJson(e)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<arrow::error::ArrowError> for Error {
    fn from(e: arrow::error::ArrowError) -> Self {
        Error::Arrow(e)
    }
}

impl From<flatbuffers::InvalidFlatbuffer> for Error {
    fn from(e: flatbuffers::InvalidFlatbuffer) -> Self {
        Error::InvalidFlatbuffer(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::InvalidId(e.to_string())
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidId(e.to_string())
    }
}

impl From<uuid::Error> for Error {
    fn from(e: uuid::Error) -> Self {
        Error::InvalidId(e.to_string())
    }
}
