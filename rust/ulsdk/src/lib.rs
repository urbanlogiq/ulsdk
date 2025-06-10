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

#[cfg(test)]
fn make_test_batches() -> (Vec<RecordBatch>, Vec<u8>) {
    use arrow::array::{ArrayRef, Int32Array, StringArray};
    use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
    use arrow::ipc::writer::StreamWriter;
    use std::sync::Arc;

    let mut str_vector = Vec::with_capacity(20);
    let mut int_vector = Vec::with_capacity(20);
    for i in 0..20 {
        str_vector.push(format!("test{}", i));
        int_vector.push(i as i32);
    }
    let str_array: ArrayRef = Arc::new(StringArray::from(str_vector));
    let int_array: ArrayRef = Arc::new(Int32Array::from(int_vector));
    let schema: SchemaRef = Arc::new(Schema::new(vec![
        Field::new("v", DataType::Utf8, false),
        Field::new("i", DataType::Int32, false),
    ]));
    let batch = RecordBatch::try_new(schema.clone(), vec![str_array, int_array]).unwrap();

    let mut buffer = Vec::new();

    {
        let mut writer = StreamWriter::try_new(&mut buffer, &schema).unwrap();
        writer.write(&batch).unwrap();
        writer.finish().unwrap();
    }

    (vec![batch], buffer)
}
