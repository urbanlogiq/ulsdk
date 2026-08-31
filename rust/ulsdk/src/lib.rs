// Copyright (c), CommunityLogiq Software

#![allow(clippy::too_long_first_doc_paragraph)]

#[rustfmt::skip]
pub mod types;
pub mod error;

#[rustfmt::skip]
#[cfg(not(target_arch = "wasm32"))]
pub mod api;
#[cfg(not(target_arch = "wasm32"))]
pub mod keys;
#[cfg(not(target_arch = "wasm32"))]
pub mod request_context;

use serde::de::{Error as SerdeError, Unexpected, Visitor};
use std::fmt;

#[cfg(not(target_arch = "wasm32"))]
pub mod native {
    use arrow::ipc::writer::StreamWriter;
    use arrow::record_batch::RecordBatch;
    use serde::Deserialize;
    use std::fmt::{self, Display, Formatter};
    use std::str::FromStr;

    use crate::error::Error;
    pub use crate::keys::{load_key, Key};

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum Environment {
        Prod,
        Stage,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
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

    // The IPC stream always leads with a schema message, so the reader carries the schema
    // even for a 0-row result, unlike collecting the (empty) batches.
    pub fn read_arrow_schema(bytes: &[u8]) -> Result<arrow::datatypes::SchemaRef, Error> {
        let reader = arrow::ipc::reader::StreamReader::try_new(bytes, None)?;
        Ok(reader.schema())
    }

    #[cfg(test)]
    pub(crate) fn make_test_batches() -> (Vec<RecordBatch>, Vec<u8>) {
        use arrow::array::{ArrayRef, Int32Array, StringArray};
        use arrow::datatypes::{DataType, Field, Schema, SchemaRef};
        use arrow::ipc::writer::StreamWriter;
        use std::sync::Arc;

        let mut str_vector = Vec::with_capacity(20);
        let mut int_vector = Vec::with_capacity(20);
        for i in 0..20 {
            str_vector.push(format!("test{}", i));
            int_vector.push(i);
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
}

#[cfg(not(target_arch = "wasm32"))]
pub use crate::native::*;

fn raw_id_from_str<E>(visitor: &IdVisitor, guid: &str) -> Result<[u8; 16], E>
where
    E: SerdeError,
{
    use base64::Engine;

    match guid.len() {
        24 => match base64::engine::general_purpose::STANDARD.decode(guid) {
            Ok(b) => {
                let array: [u8; 16] =
                    b.as_slice()
                        .try_into()
                        .map_err(|_: std::array::TryFromSliceError| {
                            SerdeError::invalid_value(Unexpected::Str(guid), visitor)
                        })?;
                Ok(array)
            }
            Err(_) => Err(SerdeError::invalid_value(Unexpected::Str(guid), visitor)),
        },
        38 => {
            if (guid.starts_with('"') && guid.ends_with('"'))
                || (guid.starts_with('{') && guid.ends_with('}'))
            {
                raw_id_from_str(visitor, &guid[1..guid.len() - 1])
            } else {
                Err(SerdeError::invalid_value(Unexpected::Str(guid), visitor))
            }
        }
        36 => {
            let guid = uuid::Uuid::parse_str(guid)
                .map_err(|_| SerdeError::invalid_value(Unexpected::Str(guid), visitor))?;

            Ok(*guid.as_bytes())
        }
        32 => hex::decode(guid)
            .map(|v| v.try_into().unwrap())
            .map_err(|_| SerdeError::invalid_value(Unexpected::Str(guid), visitor)),
        len => Err(SerdeError::invalid_length(len, visitor)),
    }
}

pub const CANONICAL_UUID_LENGTH: usize = 36;

fn id_to_utf8(id: &[u8; 16]) -> [u8; CANONICAL_UUID_LENGTH] {
    const ID_UTF8_CHARS: &[u8; 16] = b"0123456789abcdef";
    const ID_UTF8_POSITIONS: &[usize; 16] =
        &[0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
    const ID_UTF8_HYPHEN_POSITIONS: &[usize; 4] = &[8, 13, 18, 23];

    let mut buf = [0u8; CANONICAL_UUID_LENGTH];
    for (i, b) in id.iter().enumerate() {
        let b = *b;
        let i0 = ((b >> 4) & 0xf) as usize;
        let i1 = (b & 0xf) as usize;
        let b0 = ID_UTF8_CHARS[i0];
        let b1 = ID_UTF8_CHARS[i1];
        let idx = ID_UTF8_POSITIONS[i];
        buf[idx] = b0;
        buf[idx + 1] = b1;
    }

    for idx in ID_UTF8_HYPHEN_POSITIONS {
        buf[*idx] = b'-';
    }

    buf
}

pub trait FbsSerde {
    fn to_fbs_bytes(&self) -> Vec<u8>;
    fn from_fbs_bytes(bytes: &[u8]) -> Result<Self, flatbuffers::InvalidFlatbuffer>
    where
        Self: Sized;
}

struct IdVisitor;

impl Visitor<'_> for IdVisitor {
    type Value = [u8; 16];

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("24/32/36 byte string")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        match value.len() {
            16 => Ok(value.try_into().unwrap()),
            len => Err(SerdeError::invalid_length(len, &self)),
        }
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        raw_id_from_str(&self, value)
    }
}

struct PinnedObjectIdVisitor;

impl Visitor<'_> for PinnedObjectIdVisitor {
    type Value = ([u8; 16], Option<[u8; 16]>);

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("At least one, at most two 24/32/36 byte strings")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        let b = match value.len() {
            16 => value.try_into().unwrap(),
            len => return Err(SerdeError::invalid_length(len, &self)),
        };

        Ok((b, None))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        let mut splits = value.split("@");
        let Some(id_split) = splits.next() else {
            todo!()
        };

        let v = IdVisitor;

        let b = raw_id_from_str(&v, id_split)?;

        let cid = if let Some(cid_split) = splits.next() {
            Some(raw_id_from_str(&v, cid_split)?)
        } else {
            None
        };

        Ok((b, cid))
    }
}

#[cfg(test)]
mod tests {
    /// FlatBuffers declares defaults on fields, so the generator has to derive
    /// each enum's `#[default]` from the fields typed as it. These are every
    /// enum in the schema whose declared default is not its first variant --
    /// the case the generator used to get wrong, silently substituting a real
    /// value (`DC_BUSINESSES`, `Predicate::NONE`) for the intended one.
    #[test]
    fn enum_defaults_match_the_schema() {
        use crate::types::graph::Predicate;
        use crate::types::metadata::DatasetCategory;
        use crate::types::Schema::{DateUnit, TimeUnit};

        assert_eq!(DatasetCategory::default(), DatasetCategory::DC_HIDDEN);
        assert_eq!(Predicate::default(), Predicate::location);
        assert_eq!(DateUnit::default(), DateUnit::MILLISECOND);
        assert_eq!(TimeUnit::default(), TimeUnit::MILLISECOND);
    }
}
