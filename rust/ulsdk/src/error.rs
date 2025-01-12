// Copyright (c), CommunityLogiq Software

use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum Error {
    Unclassified(Box<dyn std::error::Error>),
    IoError(std::io::Error),
    Reqwest(reqwest::Error),
    FailedRequest(String, String, reqwest::StatusCode, String),
    SerdeJson(serde_json::error::Error),
    Arrow(arrow::error::ArrowError),
    InvalidFlatbuffer(flatbuffers::InvalidFlatbuffer),
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
            Error::IoError(err) => write!(f, "I/O Error: {}", err),
            Error::Reqwest(err) => write!(f, "API error: {}", err),
            Error::FailedRequest(endpoint, err, status, body) => write!(
                f,
                "Failed request to {}: {} ({}) Body: {}",
                endpoint, err, status, body
            ),
            Error::SerdeJson(err) => {
                write!(f, "Json deserialization error: {}", err)
            }
            Error::Arrow(err) => write!(f, "Arrow Error: {}", err),
            Error::InvalidFlatbuffer(err) => write!(f, "Invalid Flatbuffer Error: {}", err),
        }
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Unclassified(e.into())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

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
