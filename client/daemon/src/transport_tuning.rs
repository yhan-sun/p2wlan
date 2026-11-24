//! Optional negotiated extensions to the encrypted business data plane.

mod compression;
mod erasure;
mod field;
mod loss;
mod state;
mod wire;

#[cfg(test)]
mod impairment_tests;

pub(crate) use compression::Compression;
pub(crate) use state::{IngressKey, SessionKey, Tuning};
pub(crate) use wire::{decode, is_internal, queued_key, stamp, Message};
