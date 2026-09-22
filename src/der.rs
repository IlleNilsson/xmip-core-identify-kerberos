//! The DER a Kerberos token is, named the way RFC 4120 names it.
//!
//! The reader is the estate's one, `xmip-core-asn1`; this carried its own
//! until 2026-09-22, as did `authenticate/kerberos` for the sealed part of
//! the same token. What stays here is Kerberos's vocabulary: every field of
//! a Kerberos `SEQUENCE` is explicitly tagged and constructed, so a context
//! tag here is always the constructed one.

pub use asn1::{
    Element, GENERAL_STRING, INTEGER, OBJECT_IDENTIFIER as OID, OCTET_STRING, SEQUENCE, application,
};

/// The tag of `[n]`, context-specific and constructed.
#[must_use]
pub const fn context(number: u8) -> u8 {
    asn1::context(number, true)
}

#[cfg(test)]
pub(crate) mod tests {
    /// Encode one element, for the tests beside this.
    pub(crate) use asn1::tlv;
}
