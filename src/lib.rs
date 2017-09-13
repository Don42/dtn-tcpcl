#![warn(missing_docs)]
//! Implementation of DTN tcpclv4 draft
//!

extern crate byteorder;
#[macro_use]
extern crate bitflags;

use std::io::{Cursor, Read};
use std::io::{Error, ErrorKind};
use byteorder::{BigEndian, WriteBytesExt, ReadBytesExt};

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
    /// If the buffer is to short an Error is returned.
    /// If the first 4 octets of the buffer do not match the magic pattern an Error is returned.
    /// If the version parsed from the buffer is not supported an Error is returned.
    /// If the flags field contains invalid flags an Error is returned.
    /// If any of the reads fails an Error is returned.
    pub fn deserialize(buffer: &[u8]) -> std::io::Result<ContactHeader> {
        if buffer.len() < 4 {
            return Err(create_error!("buffer to short"));
        }
        if HEADER_MAGIC != buffer[0..4] {
            return Err(create_error!("magic not matched"));
        }
        let mut rdr = Cursor::new(&buffer[4..]);

        let version = rdr.read_u8()?;
        if version != 4 {
            return Err(create_error!("version not supported"));
        }
        let flags = rdr.read_u8()
            .and_then(|x| ContactHeaderFlags::from_bits_strict(x))?;
        let keep_alive = rdr.read_u16::<BigEndian>()?;
        let segment_mru = rdr.read_u64::<BigEndian>()?;
        let transfer_mru = rdr.read_u64::<BigEndian>()?;

        let eid_length = rdr.read_u16::<BigEndian>()?;
        let eid = match eid_length {
            0 => None,
            _ => {
                let mut eid_raw: Vec<u8> = Vec::new();
                rdr.take(eid_length as u64).read_to_end(&mut eid_raw)?;
                Some(String::from_utf8(eid_raw).unwrap()) // Convert parser error
            }
        };

        Ok(ContactHeader {
            version: version,
            flags: flags,
            keepalive: keep_alive,
            segment_mru: segment_mru,
            transfer_mru: transfer_mru,
            eid: eid,
        })
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
