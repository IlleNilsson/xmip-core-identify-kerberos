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
//! The same service principal is written beside the value as
//! `principal.service`, in the capability's canonical form — the host and the
//! realm in lower case — so it compares with a service principal any other
//! mechanism carried (ADR-0054). A ticket for a name that is not one, a single
//! component with no host, gains no such evidence; and the client principal,
//! sealed, gains no `principal.user` here.
//!
//! A `Negotiate` value carrying an NTLM message is `ntlm`'s and presents
//! nothing here, as does a SPNEGO continuation with no token in it. A token
//! that is Kerberos and cannot be read is an error saying why. Only a pushed
//! arrival carries a passed claim. The token is read by the capability's
//! `identify::kerberos::Ticket`, the one reader `authenticate/kerberos` reads
//! the same token with.
//!
//! Property this technology reads: `http.header.authorization`.
use context::property::HTTP_AUTHORIZATION;
use identify::authorization;
use identify::evidence;
use identify::kerberos::Ticket;
use identify::{
    IdentifyError, Presented, ServicePrincipalName, StreamArrival, TransportIdentifier,
};
use xcore::{Arriving, Mechanism};

/// The evidence name carrying the ticket's realm.
pub const REALM: &str = "kerberos.realm";
/// The evidence name carrying the service the ticket is for, without realm.
pub const SERVICE: &str = "kerberos.service";
/// The evidence name carrying the ticket's encryption type number.
pub const ENCRYPTION_TYPE: &str = "kerberos.etype";
/// The evidence name carrying the service key's version.
pub const KEY_VERSION: &str = "kerberos.kvno";
/// What [`evidence::KERBEROS_CLIENT`] says: inside the sealed parts, unread.
pub const SEALED: &str = "sealed";

/// Reads the Kerberos ticket a `Negotiate` authorization offers.
#[derive(Clone, Copy, Debug, Default)]
pub struct Kerberos;

impl TransportIdentifier for Kerberos {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::kerberos()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        let Some(token) = arrival
            .property(HTTP_AUTHORIZATION)
            .and_then(|value| authorization::under(value, "negotiate"))
        else {
            return Ok(None);
        };

        let bytes = codec::base64::decode(token)
            .map_err(|_| IdentifyError::new("the Negotiate token is not base64"))?;
        let Some(request) = Ticket::from_negotiate(&bytes)? else {
            return Ok(None);
        };

        let mut claim = Presented::passed(self.mechanism(), request.service_principal())
            .with_evidence(REALM, &request.realm)
            .with_evidence(SERVICE, request.service.join("/"))
            .with_evidence(ENCRYPTION_TYPE, request.encryption_type.to_string())
            .with_evidence(evidence::KERBEROS_CLIENT, SEALED)
            .with_proof(evidence::KERBEROS_AP_REQ, token);
        if let Some(version) = request.key_version {
            claim = claim.with_evidence(KEY_VERSION, version.to_string());
        }
        if let Some(service) = ServicePrincipalName::parse(&claim.value) {
            claim = claim.with_evidence(evidence::PRINCIPAL_SERVICE, service.to_string());
        }

        Ok(Some(claim))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use identify::kerberos::fixture;

    /// An AP-REQ for a service of these components in `EXAMPLE.COM`, its
    /// cipher naming the client as a real one would: nothing may find it.
    fn ap_req_for(service: &[&str]) -> Vec<u8> {
        fixture::ap_req(service, "EXAMPLE.COM", b"sealed:alice@EXAMPLE.COM")
    }

    fn kerberos_token() -> Vec<u8> {
        fixture::kerberos(&ap_req_for(&["HTTP", "xmip.example"]))
    }

    fn spnego_token(mechanism_token: &[u8]) -> Vec<u8> {
        fixture::spnego(mechanism_token)
    }
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn authorization(value: String) -> Vec<(String, String)> {
        vec![(HTTP_AUTHORIZATION.to_string(), value)]
    }

    fn negotiate_header() -> (String, Vec<(String, String)>) {
        let token = codec::base64::encode(&spnego_token(&kerberos_token()));
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
        assert_eq!(claim.proof(evidence::KERBEROS_AP_REQ), Some(token.as_str()));
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
                .contains(&(evidence::KERBEROS_CLIENT.to_string(), SEALED.to_string()))
        );
        let printed = format!("{claim:?}");
        assert!(!printed.contains("alice"), "nothing read the sealed part");
        assert!(!printed.contains(&token), "the token is not printed");
    }

    fn presented_for(service: &[&str]) -> Presented {
        let stream = stream();
        let token = codec::base64::encode(&ap_req_for(service));
        let facts = authorization(format!("Negotiate {token}"));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        Kerberos.identify(&arrival).expect("read").expect("a claim")
    }

    #[test]
    fn the_service_principal_is_written_beside_the_value_in_canonical_form() {
        let claim = presented_for(&["HTTP", "Xmip.Example"]);

        assert_eq!(
            claim.value, "HTTP/Xmip.Example@EXAMPLE.COM",
            "as the ticket"
        );
        assert!(claim.evidence.contains(&(
            evidence::PRINCIPAL_SERVICE.to_string(),
            "HTTP/xmip.example@example.com".to_string()
        )));
        assert!(
            claim
                .evidence
                .iter()
                .all(|(name, _)| name != evidence::PRINCIPAL_USER),
            "the client principal is sealed"
        );
    }

    #[test]
    fn a_ticket_for_a_name_with_no_host_gains_no_principal_evidence() {
        let claim = presented_for(&["xmip"]);

        assert_eq!(claim.value, "xmip@EXAMPLE.COM");
        assert!(claim.evidence.iter().all(
            |(name, _)| name != evidence::PRINCIPAL_SERVICE && name != evidence::PRINCIPAL_USER
        ));
    }

    #[test]
    fn an_ntlm_negotiate_and_another_scheme_and_no_header_present_nothing() {
        let stream = stream();
        let ntlm = codec::base64::encode(b"NTLMSSP\0\x03\0\0\0");

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
        let facts = authorization(format!("negotiate {}", codec::base64::encode(&cut)));
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);
        let failure = Kerberos.identify(&arrival).expect_err("truncated");
        assert!(
            failure
                .to_string()
                .starts_with("an element ends inside its contents"),
            "{failure}"
        );
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
