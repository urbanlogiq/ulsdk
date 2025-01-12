// Copyright (c), CommunityLogiq Software

#![allow(clippy::too_long_first_doc_paragraph)]

#[rustfmt::skip]
pub mod api;
pub mod error;
pub mod keys;
pub mod request_context;
#[rustfmt::skip]
pub mod types;

use arrow::ipc::writer::StreamWriter;
use arrow::record_batch::RecordBatch;
use serde_derive::Deserialize;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use crate::error::Error;
pub use crate::keys::{load_key, Key};

#[derive(Clone, Copy, PartialEq)]
pub enum Environment {
    Prod,
    Stage,
}

#[derive(Clone, Copy, PartialEq, Deserialize)]
pub enum Region {
    #[serde(rename = "ca")]
    CA,
    #[serde(rename = "us")]
    US,
}

impl FromStr for Region {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ca" => Ok(Self::CA),
            "us" => Ok(Self::US),
            _ => Err(Error::Unclassified(
                format!("Unknown region '{}'", s).into(),
            )),
        }
    }
}

impl Display for Region {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::CA => write!(f, "ca"),
            Self::US => write!(f, "us"),
        }
    }
}

impl std::str::FromStr for Environment {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "prod" => Ok(Self::Prod),
            "stage" => Ok(Self::Stage),
            _ => Err(Error::Unclassified(
                format!("Unknown environment '{}'", s).into(),
            )),
        }
    }
}

pub fn write_arrow_ipc(batches: &[RecordBatch]) -> Result<Vec<u8>, Error> {
    if batches.is_empty() {
        return Err(Error::Unclassified("Cannot provide zero record batches, at least one batch required in order to serialize.".into()));
    };

    let schema = batches[0].schema();
    let mut buffer = Vec::new();

    {
        let mut writer = StreamWriter::try_new(&mut buffer, &schema)?;

        for batch in batches {
            writer.write(batch)?;
        }

        writer.finish()?;
    }

    Ok(buffer)
}

pub fn read_arrow_ipc(bytes: &[u8]) -> Result<Vec<RecordBatch>, Error> {
    let reader = arrow::ipc::reader::StreamReader::try_new(bytes, None)?;
    let batches = reader
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(Error::from)?;

    Ok(batches)
}
