//! The AP-REQ a `Negotiate` token carries, and what of it is in the clear.
//!
//! RFC 4120 section 5.5.1 and 5.3, with the fields this reads marked:
//!
//! ```text
//! AP-REQ ::= [APPLICATION 14] SEQUENCE {
//!     pvno [0] INTEGER (5),   msg-type [1] INTEGER (14),   ap-options [2],
//!     ticket [3] Ticket,                                   <- read
//!     authenticator [4] EncryptedData }                    <- sealed: holds cname
//! Ticket ::= [APPLICATION 1] SEQUENCE {
//!     tkt-vno [0] INTEGER (5),
//!     realm [1] Realm,  sname [2] PrincipalName,           <- read
//!     enc-part [3] EncryptedData }                         <- etype and kvno read;
//!                                                             the cipher holds cname
//! ```
//!
//! The wrappings around it are RFC 2743 section 3.1 (`[APPLICATION 0]`, a
//! mechanism OID, the token), RFC 4121 section 4.1 (the two octets `01 00`
//! that say AP-REQ) and RFC 4178 (SPNEGO's `NegTokenInit` and
//! `NegTokenResp`, whose `mechToken` or `responseToken` is the same again).

use crate::der::{self, Element};
use identify::IdentifyError;

/// 1.3.6.1.5.5.2, SPNEGO.
const SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// 1.2.840.113554.1.2.2, Kerberos 5.
const KERBEROS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// 1.2.840.48018.1.2.2, the Kerberos 5 OID older Windows clients send.
const KERBEROS_LEGACY: &[u8] = &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// What an NTLM message starts with; `Negotiate` carries those too.
const NTLMSSP: &[u8] = b"NTLMSSP\0";
/// RFC 4121 section 4.1: the token id of an AP-REQ.
const TOKEN_AP_REQ: [u8; 2] = [0x01, 0x00];
/// The `msg-type` of an AP-REQ, and its application tag number.
const AP_REQ: u8 = 14;

/// What an AP-REQ says in the clear: the ticket's realm and the service it
/// is for. The client's name is not among it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApReq {
    /// The realm that issued the ticket, which is the service's realm.
    pub realm: String,
    /// The service principal's components: `HTTP`, `xmip.example`.
    pub service: Vec<String>,
    /// The encryption type of the ticket's sealed part: 18 is
    /// `aes256-cts-hmac-sha1-96`.
    pub encryption_type: u32,
    /// The version of the service key the ticket is sealed under, where the
    /// KDC said.
    pub key_version: Option<u32>,
}

impl ApReq {
    /// The service principal as Kerberos writes one: `HTTP/xmip.example@REALM`.
    #[must_use]
    pub fn service_principal(&self) -> String {
        format!("{}@{}", self.service.join("/"), self.realm)
    }

    /// Read a `Negotiate` token: a GSS-API token carrying Kerberos directly
    /// or under SPNEGO, or a bare AP-REQ.
    ///
    /// `None` where the token is somebody else's — an NTLM message, or a
    /// SPNEGO continuation with no token in it.
    ///
    /// # Errors
    ///
    /// Where the token is not DER, names a mechanism that is neither SPNEGO
    /// nor Kerberos, carries a Kerberos message that is not an AP-REQ, or an
    /// AP-REQ whose ticket cannot be read.
    pub fn from_token(token: &[u8]) -> Result<Option<Self>, IdentifyError> {
        if token.starts_with(NTLMSSP) {
            return Ok(None);
        }

        let (outer, _) = Element::read(token)?;
        match outer.tag {
            tag if tag == der::application(0) => Self::from_gss(outer),
            tag if tag == der::application(AP_REQ) => Self::parse(token).map(Some),
            // A NegTokenResp: the later legs of a SPNEGO exchange.
            tag if tag == der::context(1) => {
                let response = Element::expect(outer.content, der::SEQUENCE, "a NegTokenResp")?;
                Self::from_mechanism_token(response.field(2)?)
            }
            tag => Err(IdentifyError::new(format!(
                "the Negotiate token starts with tag {tag:#04x}, which is neither GSS-API, \
                 SPNEGO nor an AP-REQ"
            ))),
        }
    }

    /// RFC 2743 section 3.1: an OID, then whatever the mechanism defines.
    fn from_gss(outer: Element<'_>) -> Result<Option<Self>, IdentifyError> {
        let (mechanism, inner) = Element::read(outer.content)?;
        if mechanism.tag != der::OID {
            return Err(IdentifyError::new(
                "the GSS-API token does not start with a mechanism OID",
            ));
        }

        if mechanism.content == SPNEGO {
            let init = Element::expect(inner, der::context(0), "a NegTokenInit")?;
            let init = Element::expect(init.content, der::SEQUENCE, "a NegTokenInit")?;
            Self::from_mechanism_token(init.field(2)?)
        } else if mechanism.content == KERBEROS || mechanism.content == KERBEROS_LEGACY {
            match inner.split_at_checked(2) {
                Some((id, message)) if id == TOKEN_AP_REQ => Self::parse(message).map(Some),
                _ => Err(IdentifyError::new(
                    "the Kerberos token is not an AP-REQ: its token id is not 01 00",
                )),
            }
        } else {
            Err(IdentifyError::new(
                "the GSS-API token names a mechanism that is neither SPNEGO nor Kerberos",
            ))
        }
    }

    /// A SPNEGO `mechToken` or `responseToken`: an OCTET STRING holding the
    /// chosen mechanism's own token.
    fn from_mechanism_token(token: Option<Element<'_>>) -> Result<Option<Self>, IdentifyError> {
        match token {
            None => Ok(None),
            Some(token) if token.tag == der::OCTET_STRING => Self::from_token(token.content),
            Some(_) => Err(IdentifyError::new(
                "the SPNEGO mechanism token is not an OCTET STRING",
            )),
        }
    }

    /// Read a bare AP-REQ.
    ///
    /// # Errors
    ///
    /// Where the bytes are not an AP-REQ of Kerberos 5, or its ticket lacks
    /// a realm, a service name or a sealed part.
    pub fn parse(message: &[u8]) -> Result<Self, IdentifyError> {
        let missing = |what: &str| IdentifyError::new(format!("the AP-REQ has no {what}"));

        let request = Element::expect(message, der::application(AP_REQ), "an AP-REQ")?;
        let request = Element::expect(request.content, der::SEQUENCE, "an AP-REQ")?;
        let version = request.field(0)?.and_then(|pvno| pvno.integer());
        let kind = request.field(1)?.and_then(|kind| kind.integer());
        if version != Some(5) || kind != Some(u32::from(AP_REQ)) {
            return Err(IdentifyError::new(
                "the AP-REQ is not Kerberos 5 message type 14",
            ));
        }

        let ticket = request.field(3)?.ok_or_else(|| missing("ticket"))?;
        if ticket.tag != der::application(1) {
            return Err(IdentifyError::new("the AP-REQ's ticket is not a Ticket"));
        }
        let ticket = Element::expect(ticket.content, der::SEQUENCE, "a Ticket")?;

        let realm = ticket
            .field(1)?
            .and_then(|realm| realm.text())
            .filter(|realm| !realm.is_empty())
            .ok_or_else(|| missing("realm in its ticket"))?;
        let service = ticket
            .field(2)?
            .ok_or_else(|| missing("service name in its ticket"))?
            .field(1)?
            .ok_or_else(|| missing("service name in its ticket"))?
            .children()?
            .iter()
            .map(|component| component.text().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .filter(|components| !components.is_empty())
            .ok_or_else(|| missing("readable service name in its ticket"))?;
        let sealed = ticket
            .field(3)?
            .ok_or_else(|| missing("sealed part in its ticket"))?;

        Ok(Self {
            realm: realm.to_string(),
            service,
            encryption_type: sealed
                .field(0)?
                .and_then(|etype| etype.integer())
                .ok_or_else(|| missing("encryption type on its ticket"))?,
            key_version: sealed.field(1)?.and_then(|kvno| kvno.integer()),
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::der::tests::tlv;
    use crate::der::{GENERAL_STRING, INTEGER, OCTET_STRING, OID, SEQUENCE, application, context};

    fn field(number: u8, inner: &[u8]) -> Vec<u8> {
        tlv(context(number), inner)
    }

    fn sealed(kvno: Option<u8>) -> Vec<u8> {
        let mut fields = field(0, &tlv(INTEGER, &[18]));
        if let Some(kvno) = kvno {
            fields.extend(field(1, &tlv(INTEGER, &[kvno])));
        }
        // The cipher text names the client, as it would: nothing may find it.
        fields.extend(field(2, &tlv(OCTET_STRING, b"sealed:alice@EXAMPLE.COM")));
        tlv(SEQUENCE, &fields)
    }

    /// An AP-REQ for `HTTP/xmip.example@EXAMPLE.COM`, as a KDC's ticket and
    /// a client's authenticator would make it.
    pub(crate) fn ap_req() -> Vec<u8> {
        ap_req_for(&["HTTP", "xmip.example"])
    }

    /// An AP-REQ for a service of these components, in `EXAMPLE.COM`.
    pub(crate) fn ap_req_for(service: &[&str]) -> Vec<u8> {
        let names = service
            .iter()
            .map(|component| tlv(GENERAL_STRING, component.as_bytes()))
            .collect::<Vec<_>>()
            .concat();
        let sname = tlv(
            SEQUENCE,
            &[
                field(0, &tlv(INTEGER, &[2])),
                field(1, &tlv(SEQUENCE, &names)),
            ]
            .concat(),
        );
        let ticket = tlv(
            application(1),
            &tlv(
                SEQUENCE,
                &[
                    field(0, &tlv(INTEGER, &[5])),
                    field(1, &tlv(GENERAL_STRING, b"EXAMPLE.COM")),
                    field(2, &sname),
                    field(3, &sealed(Some(3))),
                ]
                .concat(),
            ),
        );
        tlv(
            application(AP_REQ),
            &tlv(
                SEQUENCE,
                &[
                    field(0, &tlv(INTEGER, &[5])),
                    field(1, &tlv(INTEGER, &[AP_REQ])),
                    field(2, &tlv(0x03, &[0, 0, 0, 0, 0])),
                    field(3, &ticket),
                    field(4, &sealed(None)),
                ]
                .concat(),
            ),
        )
    }

    /// RFC 2743 framing around a mechanism's token.
    pub(crate) fn gss(mechanism: &[u8], inner: &[u8]) -> Vec<u8> {
        tlv(
            application(0),
            &[tlv(OID, mechanism), inner.to_vec()].concat(),
        )
    }

    pub(crate) fn kerberos_token() -> Vec<u8> {
        gss(KERBEROS, &[TOKEN_AP_REQ.to_vec(), ap_req()].concat())
    }

    /// What a browser sends: SPNEGO offering Kerberos, the AP-REQ inside.
    pub(crate) fn spnego_token(mechanism_token: &[u8]) -> Vec<u8> {
        let init = tlv(
            SEQUENCE,
            &[
                field(0, &tlv(SEQUENCE, &tlv(OID, KERBEROS))),
                field(2, &tlv(OCTET_STRING, mechanism_token)),
            ]
            .concat(),
        );
        gss(SPNEGO, &tlv(context(0), &init))
    }

    #[test]
    fn the_realm_and_the_service_are_read_out_of_the_ticket() {
        let request = ApReq::parse(&ap_req()).expect("an AP-REQ");

        assert_eq!(request.realm, "EXAMPLE.COM");
        assert_eq!(request.service, ["HTTP", "xmip.example"]);
        assert_eq!(request.service_principal(), "HTTP/xmip.example@EXAMPLE.COM");
        assert_eq!(request.encryption_type, 18);
        assert_eq!(request.key_version, Some(3));
    }

    #[test]
    fn an_ap_req_is_found_under_spnego_under_gss_api_and_bare() {
        let expected = ApReq::parse(&ap_req()).expect("an AP-REQ");

        for token in [spnego_token(&kerberos_token()), kerberos_token(), ap_req()] {
            assert_eq!(
                ApReq::from_token(&token).expect("read"),
                Some(expected.clone())
            );
        }

        let legacy = gss(KERBEROS_LEGACY, &[TOKEN_AP_REQ.to_vec(), ap_req()].concat());
        assert_eq!(ApReq::from_token(&legacy).expect("read"), Some(expected));
    }

    #[test]
    fn an_ntlm_message_and_an_empty_continuation_are_somebody_elses() {
        let ntlm = b"NTLMSSP\0\x03\0\0\0";
        let response = tlv(context(1), &tlv(SEQUENCE, &field(0, &tlv(0x0a, &[1]))));

        assert_eq!(ApReq::from_token(ntlm).expect("read"), None);
        assert_eq!(ApReq::from_token(&spnego_token(ntlm)).expect("read"), None);
        assert_eq!(ApReq::from_token(&response).expect("read"), None);
    }

    #[test]
    fn a_kerberos_message_that_is_not_an_ap_req_is_refused_with_the_reason() {
        let reply = gss(KERBEROS, &[vec![0x02, 0x00], ap_req()].concat());
        let failure = ApReq::from_token(&reply).expect_err("an AP-REP");
        assert!(failure.message.contains("not an AP-REQ"), "{failure}");

        let other = gss(&[0x2a, 0x03], &[]);
        let failure = ApReq::from_token(&other).expect_err("another mechanism");
        assert!(failure.message.contains("neither SPNEGO nor Kerberos"));

        let mut truncated = kerberos_token();
        truncated.truncate(40);
        assert!(ApReq::from_token(&truncated).is_err());
    }
}
