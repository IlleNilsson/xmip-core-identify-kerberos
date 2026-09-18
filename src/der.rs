//! As much DER as a Kerberos token needs, and no more.
//!
//! X.690: every element is a tag octet, a length and that many content
//! octets. Kerberos and SPNEGO use only low tag numbers, so the tag is one
//! octet here and a high-tag-number form is refused; the length is the short
//! form or a long form of up to four octets. Nothing is copied: an
//! [`Element`] borrows its content from the token it was read out of.

use identify::IdentifyError;

/// `SEQUENCE`, constructed.
pub const SEQUENCE: u8 = 0x30;
/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// `GeneralString`, which RFC 4120 uses for every name.
pub const GENERAL_STRING: u8 = 0x1b;

/// The tag of `[APPLICATION n]`, constructed.
#[must_use]
pub const fn application(number: u8) -> u8 {
    0x60 | number
}

/// The tag of `[n]`, context-specific and constructed.
#[must_use]
pub const fn context(number: u8) -> u8 {
    0xa0 | number
}

/// One element: its tag octet and its content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Element<'a> {
    pub tag: u8,
    pub content: &'a [u8],
}

impl<'a> Element<'a> {
    /// Read the element at the head of `input`, and what follows it.
    ///
    /// # Errors
    ///
    /// Where the input ends inside the element, the tag is in the
    /// high-tag-number form, or the length is indefinite or longer than four
    /// octets.
    pub fn read(input: &'a [u8]) -> Result<(Self, &'a [u8]), IdentifyError> {
        let truncated = || IdentifyError::new("the DER ends inside an element");

        let (&tag, rest) = input.split_first().ok_or_else(truncated)?;
        if tag & 0x1f == 0x1f {
            return Err(IdentifyError::new(
                "the DER holds a high-tag-number element, which no Kerberos token has",
            ));
        }

        let (&first, rest) = rest.split_first().ok_or_else(truncated)?;
        let (length, rest) = if first & 0x80 == 0 {
            (usize::from(first), rest)
        } else {
            let octets = usize::from(first & 0x7f);
            if octets == 0 || octets > 4 {
                return Err(IdentifyError::new(
                    "the DER holds a length that is indefinite or longer than four octets",
                ));
            }
            let (length, rest) = rest.split_at_checked(octets).ok_or_else(truncated)?;
            let length = length
                .iter()
                .fold(0_usize, |sum, octet| (sum << 8) | usize::from(*octet));
            (length, rest)
        };

        let (content, rest) = rest.split_at_checked(length).ok_or_else(truncated)?;
        Ok((Self { tag, content }, rest))
    }

    /// Read the element at the head of `input` and require its tag.
    ///
    /// # Errors
    ///
    /// As [`Element::read`], and where the tag is another: the error names
    /// `what` was expected.
    pub fn expect(input: &'a [u8], tag: u8, what: &str) -> Result<Self, IdentifyError> {
        let (element, _) = Self::read(input)?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(IdentifyError::new(format!(
                "expected {what} (tag {tag:#04x}) and found tag {:#04x}",
                element.tag
            )))
        }
    }

    /// The elements inside this one, in order.
    ///
    /// # Errors
    ///
    /// As [`Element::read`], for any of them.
    pub fn children(&self) -> Result<Vec<Element<'a>>, IdentifyError> {
        let mut children = Vec::new();
        let mut rest = self.content;
        while !rest.is_empty() {
            let (child, after) = Self::read(rest)?;
            children.push(child);
            rest = after;
        }
        Ok(children)
    }

    /// What `[number]` wraps among this element's children, where it is
    /// there: the fields of a Kerberos `SEQUENCE` are all explicitly tagged.
    ///
    /// # Errors
    ///
    /// As [`Element::read`].
    pub fn field(&self, number: u8) -> Result<Option<Element<'a>>, IdentifyError> {
        self.children()?
            .into_iter()
            .find(|child| child.tag == context(number))
            .map(|wrapper| Self::read(wrapper.content).map(|(inner, _)| inner))
            .transpose()
    }

    /// The content as a non-negative `INTEGER` that fits 32 bits, which
    /// every number read here does.
    #[must_use]
    pub fn integer(&self) -> Option<u32> {
        if self.tag != INTEGER || self.content.is_empty() || self.content[0] & 0x80 != 0 {
            return None;
        }
        let digits = match self.content {
            [0, rest @ ..] => rest,
            all => all,
        };
        (digits.len() <= 4).then(|| {
            digits
                .iter()
                .fold(0_u32, |sum, octet| (sum << 8) | u32::from(*octet))
        })
    }

    /// The content as the text of a `GeneralString`.
    #[must_use]
    pub fn text(&self) -> Option<&'a str> {
        (self.tag == GENERAL_STRING)
            .then(|| core::str::from_utf8(self.content).ok())
            .flatten()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Encode one element, for the tests here and beside.
    pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag];
        match content.len() {
            length @ 0..=0x7f => bytes.push(u8::try_from(length).expect("fits")),
            length @ 0x80..=0xff => bytes.extend([0x81, u8::try_from(length).expect("fits")]),
            length => {
                let length = u16::try_from(length).expect("a test token under 64 KiB");
                bytes.push(0x82);
                bytes.extend(length.to_be_bytes());
            }
        }
        bytes.extend(content);
        bytes
    }

    #[test]
    fn an_element_is_read_with_a_short_and_with_a_long_length() {
        let short = tlv(GENERAL_STRING, b"EXAMPLE.COM");
        let (element, rest) = Element::read(&short).expect("read");
        assert_eq!(element.text(), Some("EXAMPLE.COM"));
        assert!(rest.is_empty());

        let mut long = tlv(OCTET_STRING, &[7; 300]);
        long.push(0xff);
        let (element, rest) = Element::read(&long).expect("read");
        assert_eq!(element.content.len(), 300);
        assert_eq!(rest, [0xff]);
    }

    #[test]
    fn a_tagged_field_is_found_among_its_siblings_and_unwrapped() {
        let sequence = tlv(
            SEQUENCE,
            &[
                tlv(context(0), &tlv(INTEGER, &[5])),
                tlv(context(1), &tlv(INTEGER, &[0, 0x80])),
            ]
            .concat(),
        );
        let (sequence, _) = Element::read(&sequence).expect("read");

        let second = sequence.field(1).expect("read").expect("there");

        assert_eq!(second.integer(), Some(128));
        assert_eq!(sequence.field(3).expect("read"), None);
    }

    #[test]
    fn an_element_that_runs_past_the_end_is_refused_with_the_reason() {
        let mut bytes = tlv(SEQUENCE, &[1, 2, 3, 4]);
        bytes.truncate(4);

        let failure = Element::read(&bytes).expect_err("truncated");

        assert_eq!(failure.to_string(), "the DER ends inside an element");
        assert!(Element::read(&[0x30, 0x80]).is_err(), "indefinite length");
        assert!(Element::read(&[0x1f, 0x01, 0x00]).is_err(), "high tag");
    }

    #[test]
    fn an_unexpected_tag_names_what_was_expected() {
        let bytes = tlv(INTEGER, &[5]);

        let failure = Element::expect(&bytes, SEQUENCE, "a Ticket").expect_err("an INTEGER");

        assert!(failure.message.contains("a Ticket"), "{failure}");
    }
}
