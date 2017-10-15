#![warn(missing_docs)]
//! Implementation of DTN tcpclv4 draft
//!

extern crate byteorder;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate nom;

use std::io::{Cursor, Read};
use std::io::{Error, ErrorKind};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

use nom::{IResult, be_u8, be_u16, be_u64};

/// Magic Bytes of the Contact Header
const HEADER_MAGIC: [u8; 4] = [0x64, 0x74, 0x6e, 0x21];  // dtn!
/// Length of Contact Header up to the eid
const CONTACT_HEADER_BASE_LENGTH: usize = 24;


macro_rules! create_error {
    ( $x:expr ) =>  {
        {
            Error::new(ErrorKind::Other, $x)
        }
    };
}


#[derive(Debug)]
/// Contact Header
pub struct ContactHeader {
    version: u8,
    flags: ContactHeaderFlags,
    keepalive: u16,
    segment_mru: u64,
    transfer_mru: u64,
    eid: Option<String>,
}

bitflags! {
/// Flags defined for Contact Headers
pub struct ContactHeaderFlags: u8 {
    /// This node is able to use TLS
    const CAN_TLS = 0x01;
}}

impl ContactHeaderFlags {
    /// Try and parse a octet as a bit flag field
    ///
    /// # Errors
    /// If any flags are set that are not defined in the struct, an Error is returned.
    pub fn from_bits_strict(bits: u8) -> std::io::Result<ContactHeaderFlags> {
        ContactHeaderFlags::from_bits(bits)
            .ok_or(create_error!("unknown bitflags detected"))
    }
}


impl ContactHeader {
    /// Create a new Contact Header
    pub fn new() -> ContactHeader {
        ContactHeader {
            version: 4,
            flags: ContactHeaderFlags::empty(),
            keepalive: 0,
            segment_mru: 0,
            transfer_mru: 0,
            eid: None,
        }
    }

    /// Set eid in the Contact Header
    ///
    /// # Errors
    /// If the eid is to long to be encoded in the Contact Header, an Error is returned.
    /// The size of the eid must fit in a u16.
    pub fn eid<S: Into<String>>(&mut self, eid: S) -> std::io::Result<&mut ContactHeader> {
        let eid: String = eid.into();
        if eid.as_bytes().len() > std::u16::MAX as usize {
            return Err(create_error!("eid to long"));
        }
        self.eid = Some(eid);
        Ok(self)
    }

    /// Set flags in the Contact Header
    pub fn flags(&mut self, flags: ContactHeaderFlags) -> &mut ContactHeader {
        self.flags = flags;
        self
    }

    /// Set the keepalive in the Contact Header
    pub fn keepalive(&mut self, keepalive: u16) -> &mut ContactHeader {
        self.keepalive = keepalive;
        self
    }

    /// Set segment mru in the Contact Header
    pub fn segment_mru(&mut self, segment_mru: u64) -> &mut ContactHeader {
        self.segment_mru = segment_mru;
        self
    }

    /// Set transfer mru in the Contact Header
    pub fn transfer_mru(&mut self, transfer_mru: u64) -> &mut ContactHeader {
        self.transfer_mru = transfer_mru;
        self
    }

    /// Set a single flag in the Contact Header
    pub fn set_flag<F>(&mut self, flag: F)
        where F: Into<ContactHeaderFlags> {
        self.flags.insert(flag.into())
    }

    /// Unset a single flag in the Contact Header
    pub fn unset_flag<F>(&mut self, flag: F)
        where F: Into<ContactHeaderFlags> {
        self.flags.remove(flag.into());
    }

    /// Unset all flags in the Contact Header
    pub fn clear_flags(&mut self) {
        self.flags = ContactHeaderFlags::empty();
    }

    /// Serialize the Contact Header to a byte vector
    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::with_capacity(
            CONTACT_HEADER_BASE_LENGTH +
                self.eid
                    .as_ref()
                    .map_or(0, |eid| eid.as_bytes().len()));
        buffer.extend(HEADER_MAGIC.iter());
        buffer.write_u8(self.version).unwrap();
        buffer.write_u8(self.flags.bits).unwrap();
        buffer.write_u16::<BigEndian>(self.keepalive).unwrap();
        buffer.write_u64::<BigEndian>(self.segment_mru).unwrap();
        buffer.write_u64::<BigEndian>(self.transfer_mru).unwrap();
        match self.eid.as_ref() {
            Some(eid) => {
                let eid_bytes = eid.as_bytes();
                assert!(eid_bytes.len() <= std::u16::MAX as usize);
                buffer.write_u16::<BigEndian>(eid_bytes.len() as u16).unwrap();
                buffer.extend(eid_bytes);
            }
            None => buffer.write_u16::<BigEndian>(0).unwrap(),
        }

        buffer
    }

    /// Parse the Contact Header from a byte slice
    ///
    /// # Panics
    /// If the eid is not valid UTF-8 this function panics.
    /// This panic will be transformed to an Error in the future.
    ///
    /// # Errors
    /// If the first 4 octets of the buffer do not match the magic pattern an Error is returned.
    /// If the version parsed from the buffer is not supported an Error is returned.
    /// If the flags field contains invalid flags an Error is returned.
    /// If any of the reads fails an Error is returned.
    pub fn deserialize(i: &[u8]) -> IResult<&[u8], ContactHeader> {
        contact_header(i)
    }
}

named!(version< &[u8], u8>, map_opt!(be_u8,
    |x: u8| -> Option<u8> {
        match x {
        0x04 => Some(0x04),
        _ => None,
        }}));
named!(header_flags< &[u8], ContactHeaderFlags>, map_opt!(be_u8,
    |x: u8| -> Option<ContactHeaderFlags> {
        ContactHeaderFlags::from_bits(x)
    }));
named!(parse_eid< &[u8], Option<String> >,
    do_parse!(
        size: be_u16 >>
        raw_eid: take!(size) >>
        (match size {
            0 => None,
            _ => Some(String::from_utf8(raw_eid.to_vec()).unwrap()),
        })
));
named!(contact_header<ContactHeader>,
    do_parse!(
        tag!(HEADER_MAGIC) >>
        version: version >>
        flags: header_flags >>
        keepalive: be_u16 >>
        segment_mru: be_u64 >>
        transfer_mru: be_u64 >>
        eid: parse_eid >>
        (ContactHeader {
        version: version,
        flags: flags,
        keepalive: keepalive,
        segment_mru: segment_mru,
        transfer_mru: transfer_mru,
        eid: eid })
));


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test simple creation of a default header
    fn test_init_contact_header() {
        let contact_header = ContactHeader::new();
        assert_eq!(contact_header.eid, None);
        assert_eq!(contact_header.version, 4);
        assert_eq!(contact_header.flags, super::ContactHeaderFlags::empty());
        assert_eq!(contact_header.transfer_mru, 0);
        assert_eq!(contact_header.segment_mru, 0);
    }

    #[test]
    /// Test setting and unsetting a flag
    fn test_set_unset_flag() {
        let mut contact_header = ContactHeader::new();
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
        contact_header.set_flag(CAN_TLS);
        assert_eq!(contact_header.flags.bits(), 0x01);
        assert_eq!(contact_header.flags, CAN_TLS);
        contact_header.unset_flag(CAN_TLS);
        assert_eq!(contact_header.flags.bits(), 0x00);
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
    }

    #[test]
    /// Test clearing the bitfield
    fn test_set_clear_flag() {
        let mut contact_header = ContactHeader::new();
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
        contact_header.set_flag(CAN_TLS);
        assert_eq!(contact_header.flags, CAN_TLS);
        contact_header.clear_flags();
        assert_eq!(contact_header.flags.bits(), 0x00);
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
    }

    #[test]
    /// Test setting the same flags twice
    ///
    /// This should behave the same way as setting it only once.
    fn test_duplicate_set() {
        let mut contact_header = ContactHeader::new();
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
        contact_header.set_flag(CAN_TLS);
        assert_eq!(contact_header.flags, CAN_TLS);
        contact_header.set_flag(CAN_TLS);
        assert_eq!(contact_header.flags, CAN_TLS);
        contact_header.unset_flag(CAN_TLS);
        assert_eq!(contact_header.flags, ContactHeaderFlags::empty());
    }
}
