#![forbid(unsafe_code)]

//! Identify by kerberos: the ticket a `Negotiate` authorization offers, read
//! as far as it can be read and not verified.
//!
//! RFC 4559 carries Kerberos over HTTP as `Authorization: Negotiate
//! <base64>`: a GSS-API token, almost always SPNEGO, whose mechanism token is
//! a Kerberos AP-REQ — a service ticket the KDC sealed under the service's
//! key, and an authenticator the client sealed under the session key inside
//! it. This identifier unwraps the token, reads the AP-REQ, and presents a
//! claim under [`xcore::mechanism::kerberos`], passed, with the whole token
//! riding on [`Presented::proof`] as `kerberos.ap-req` for
//! `authenticate/kerberos` to open with the node's keytab.
//!
//! **The client principal is not in the clear, and this does not pretend it
//! is.** ADR-0050 gives this technology "a ticket's client principal,
//! unverified", but RFC 4120 puts `cname` in exactly two places in an AP-REQ
//! — the ticket's `EncTicketPart` and the `Authenticator` — and both are
//! sealed. Nothing short of the service key reads them, and holding the
//! service key is the second gate's business. What an AP-REQ does say in the
//! clear is whom the ticket is *for*, so that is what is presented:
//!
//! ```text
//! value                 HTTP/xmip.example@EXAMPLE.COM   the service principal of the ticket
//! kerberos.realm        EXAMPLE.COM                     evidence
//! kerberos.service      HTTP/xmip.example               evidence
//! kerberos.etype        18                              evidence: the ticket's encryption type
//! kerberos.kvno         3                               evidence, where the KDC said
//! kerberos.client       sealed                          evidence: said, so nobody looks for it
//! kerberos.ap-req       the base64 after Negotiate      proof
//! ```
//!
//! The claim reads "somebody holding a ticket for this service in this
//! realm", which is true, recordable, and enough to pick the keytab entry
//! by. The verified value the second gate answers with is the client
//! principal, and that — not this — is what resolves to a Party.
//!
//! A `Negotiate` value carrying an NTLM message is `ntlm`'s and presents
//! nothing here, as does a SPNEGO continuation with no token in it. A token
//! that is Kerberos and cannot be read is an error saying why. Only a pushed
//! arrival carries a passed claim. The DER reading is [`der`], as small as
//! the token needs; the token's shape is [`ap_req`].
//!
//! Property this technology reads: `http.header.authorization`.

pub mod ap_req;
pub mod der;

use ap_req::ApReq;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier};
use xcore::{Arriving, Mechanism};

/// The property read: the HTTP `Authorization` header.
pub const AUTHORIZATION: &str = "http.header.authorization";
/// The evidence name carrying the ticket's realm.
pub const REALM: &str = "kerberos.realm";
/// The evidence name carrying the service the ticket is for, without realm.
pub const SERVICE: &str = "kerberos.service";
/// The evidence name carrying the ticket's encryption type number.
pub const ENCRYPTION_TYPE: &str = "kerberos.etype";
/// The evidence name carrying the service key's version.
pub const KEY_VERSION: &str = "kerberos.kvno";
/// The evidence name saying where the client principal is.
pub const CLIENT: &str = "kerberos.client";
/// What [`CLIENT`] says: inside the sealed parts, unread.
pub const SEALED: &str = "sealed";
/// The proof name the base64 token rides under, read by
/// `authenticate/kerberos`.
pub const AP_REQ_PROOF: &str = "kerberos.ap-req";

/// Reads the Kerberos ticket a `Negotiate` authorization offers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Kerberos;

/// The base64 after `Negotiate`, or `None` for any other scheme.
fn negotiate(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization
        .trim()
        .split_once(|character: char| character.is_ascii_whitespace())?;

    scheme
        .eq_ignore_ascii_case("negotiate")
        .then(|| token.trim())
}

impl TransportIdentifier for Kerberos {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::kerberos()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(token) = arrival.property(AUTHORIZATION).and_then(negotiate) else {
            return Ok(None);
        };

        let bytes = STANDARD
            .decode(token)
            .map_err(|_| IdentifyError::new("the Negotiate token is not base64"))?;
        let Some(request) = ApReq::from_token(&bytes)? else {
            return Ok(None);
        };

        let mut claim = Presented::passed(self.mechanism(), request.service_principal())
            .with_evidence(REALM, &request.realm)
            .with_evidence(SERVICE, request.service.join("/"))
            .with_evidence(ENCRYPTION_TYPE, request.encryption_type.to_string())
            .with_evidence(CLIENT, SEALED)
            .with_proof(AP_REQ_PROOF, token);
        if let Some(version) = request.key_version {
            claim = claim.with_evidence(KEY_VERSION, version.to_string());
        }

        Ok(Some(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ap_req::tests::{kerberos_token, spnego_token};
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn authorization(value: String) -> Vec<(String, String)> {
        vec![(AUTHORIZATION.to_string(), value)]
    }

    fn negotiate_header() -> (String, Vec<(String, String)>) {
        let token = STANDARD.encode(spnego_token(&kerberos_token()));
        let facts = authorization(format!("Negotiate {token}"));
        (token, facts)
    }

    #[test]
    fn a_negotiate_ticket_is_presented_by_the_service_it_is_for_with_the_token_as_proof() {
        let stream = stream();
        let (token, facts) = negotiate_header();
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = Kerberos.identify(&arrival).expect("read").expect("a claim");

        assert_eq!(claim.mechanism.name(), "kerberos");
        assert_eq!(claim.value, "HTTP/xmip.example@EXAMPLE.COM");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.proof(AP_REQ_PROOF), Some(token.as_str()));
        for (name, value) in [
            (REALM, "EXAMPLE.COM"),
            (SERVICE, "HTTP/xmip.example"),
            (ENCRYPTION_TYPE, "18"),
            (KEY_VERSION, "3"),
        ] {
            assert!(
                claim
                    .evidence
                    .contains(&(name.to_string(), value.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn the_client_principal_is_sealed_and_the_record_says_so_rather_than_guessing() {
        let stream = stream();
        let (token, facts) = negotiate_header();
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = Kerberos.identify(&arrival).expect("read").expect("a claim");

        assert!(
            claim
                .evidence
                .contains(&(CLIENT.to_string(), SEALED.to_string()))
        );
        let printed = format!("{claim:?}");
        assert!(!printed.contains("alice"), "nothing read the sealed part");
        assert!(!printed.contains(&token), "the token is not printed");
    }

    #[test]
    fn an_ntlm_negotiate_and_another_scheme_and_no_header_present_nothing() {
        let stream = stream();
        let ntlm = STANDARD.encode(b"NTLMSSP\0\x03\0\0\0");

        for facts in [
            authorization(format!("Negotiate {ntlm}")),
            authorization("Basic cGFydG5lci14OnMzY3IzdA==".to_string()),
            authorization("Negotiate".to_string()),
            Vec::new(),
        ] {
            let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

            assert!(Kerberos.identify(&arrival).expect("read").is_none());
        }
    }

    #[test]
    fn a_token_that_is_not_base64_or_not_a_ticket_is_an_error_naming_why() {
        let stream = stream();

        let facts = authorization("Negotiate not*base64".to_string());
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);
        let failure = Kerberos.identify(&arrival).expect_err("not base64");
        assert_eq!(failure.to_string(), "the Negotiate token is not base64");

        let mut cut = spnego_token(&kerberos_token());
        cut.truncate(60);
        let facts = authorization(format!("negotiate {}", STANDARD.encode(cut)));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);
        let failure = Kerberos.identify(&arrival).expect_err("truncated");
        assert_eq!(failure.to_string(), "the DER ends inside an element");
    }

    #[test]
    fn a_scheduled_pickup_presents_nothing_because_the_ticket_was_xmips_own() {
        let stream = stream();
        let (_, facts) = negotiate_header();
        let arrival =
            StreamArrival::new(&stream, Arriving::Scheduled, "https://partner/out", &facts);

        assert!(Kerberos.identify(&arrival).expect("read").is_none());
    }
}
