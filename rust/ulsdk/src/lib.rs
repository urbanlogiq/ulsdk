// Copyright (c), CommunityLogiq Software

pub mod error;
pub mod keys;
pub mod request_context;

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
