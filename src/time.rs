//! Time-related constituent elements.
use crate::util::{ReadBytesExt, WriteBytesExt};
use crate::{Error, Result};
use std::io::{Read, Write};

/// Timestamp type for PTS/DTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(u64);
impl Timestamp {
    /// 90 kHz.
    pub const RESOLUTION: u64 = 90_000;

    /// Maximum timestamp value.
    pub const MAX: u64 = (1 << 33) - 1;

    /// Makes a new `Timestamp` instance.
    ///
    /// # Errors
    ///
    /// If `n` exceeds `Timestamp::MAX`, it will return an `ErrorKind::InvalidInput` error.
    pub fn new(n: u64) -> Result<Self> {
        if n > Self::MAX {
            return Err(Error::invalid_input(format!("Too large value: {n}")));
        }
        Ok(Timestamp(n))
    }

    /// Returns the value of the timestamp.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub(crate) fn from_u64(n: u64) -> Result<Self> {
        if (n & 1) == 0 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }
        if ((n >> 16) & 1) == 0 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }
        if ((n >> 32) & 1) == 0 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }

        let n0 = n >> (32 + 1) & ((1 << 3) - 1);
        let n1 = n >> (16 + 1) & ((1 << 15) - 1);
        let n2 = n >> 1 & ((1 << 15) - 1);
        Ok(Timestamp((n0 << 30) | (n1 << 15) | n2))
    }

    pub(crate) fn read_from<R: Read>(mut reader: R, check_bits: u8) -> Result<Self> {
        let n = reader.read_uint::<5>()?;
        if (n >> 36) as u8 != check_bits {
            return Err(Error::invalid_input(format!(
                "Expected check_bits: {check_bits}, got: {}",
                (n >> 36) as u8
            )));
        }
        Self::from_u64(n)
    }

    /// Writes the 5-byte PTS/DTS representation of the timestamp to the
    /// given writer, including the marker bits and the 4-bit `check_bits`
    /// prefix (`0b0010` for a lone PTS, `0b0011`/`0b0001` for PTS/DTS pairs).
    pub fn write_to<W: Write>(&self, mut writer: W, check_bits: u8) -> Result<()> {
        let n0 = u64::from(check_bits);
        let n1 = self.0 >> 30;
        let n2 = (self.0 >> 15) & ((1 << 15) - 1);
        let n3 = self.0 & ((1 << 15) - 1);

        let n = (n0 << 36) | (n1 << 33) | (1 << 32) | (n2 << 17) | (1 << 16) | (n3 << 1) | 1;
        writer.write_uint::<5>(n)?;
        Ok(())
    }

    /// Encodes the timestamp into a 5-byte big-endian array, including the
    /// marker bits and the 4-bit `check_bits` prefix.
    ///
    /// This is a byte-level convenience wrapper around
    /// [`Timestamp::write_to`][Self::write_to] for callers that want the
    /// encoded bytes directly.
    pub fn to_bytes(self, check_bits: u8) -> [u8; 5] {
        let mut buf = [0; 5];
        self.write_to(&mut buf[..], check_bits)
            .expect("unreachable: writing 5 bytes into a 5-byte buffer");
        buf
    }
}
impl From<u32> for Timestamp {
    fn from(n: u32) -> Self {
        Timestamp(u64::from(n))
    }
}

/// Timestamp type for PCR/OPCR/ESCR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClockReference(u64);
impl ClockReference {
    /// 27MHz.
    pub const RESOLUTION: u64 = 27_000_000;

    /// Maximum PCR value.
    pub const MAX: u64 = ((1 << 33) - 1) * 300 + 0b1_1111_1111;

    /// Makes a new `ClockReference` instance.
    ///
    /// # Errors
    ///
    /// If `n` exceeds `ClockReference::MAX`, it will return an `ErrorKind::InvalidInput` error.
    pub fn new(n: u64) -> Result<Self> {
        if n > Self::MAX {
            return Err(Error::invalid_input(format!("Too large value: {n}")));
        }
        Ok(ClockReference(n))
    }

    /// Returns the value of the PCR.
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    pub(crate) fn read_pcr_from<R: Read>(mut reader: R) -> Result<Self> {
        let n = reader.read_uint::<6>()?;
        let base = n >> 15;
        let extension = n & 0b1_1111_1111;
        Ok(ClockReference(base * 300 + extension))
    }

    /// Writes the 6-byte PCR representation of the clock reference to the
    /// given writer (33-bit base, 6 zero reserved bits, 9-bit extension).
    ///
    /// Note that [`ClockReference::pcr_to_bytes`][Self::pcr_to_bytes] emits
    /// the spec-conformant `'111111'` reserved bits instead.
    pub fn write_pcr_to<W: Write>(&self, mut writer: W) -> Result<()> {
        let base = self.0 / 300;
        let extension = self.0 % 300;

        let n = (base << 15) | extension;
        writer.write_uint::<6>(n)?;
        Ok(())
    }

    /// Encodes the clock reference into a 6-byte big-endian PCR array:
    /// 33-bit base, 6 reserved bits set to `'111111'`, 9-bit extension,
    /// as required by ISO/IEC 13818-1 §2.4.4.9 (and as emitted by ffmpeg).
    pub fn pcr_to_bytes(self) -> [u8; 6] {
        let base = self.0 / 300;
        let extension = self.0 % 300;
        [
            (base >> 25) as u8,
            (base >> 17) as u8,
            (base >> 9) as u8,
            (base >> 1) as u8,
            (((base & 1) << 7) | 0x7E | u64::from(extension >> 8)) as u8,
            (extension & 0xFF) as u8,
        ]
    }

    pub(crate) fn read_escr_from<R: Read>(mut reader: R) -> Result<Self> {
        let n = reader.read_uint::<6>()?;
        if n >> 46 != 0 {
            return Err(Error::invalid_input("Expected zero in reserved bits"));
        }

        if (n & 1) != 1 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }
        let extension = (n >> 1) & 0b1_1111_1111;

        let n = n >> 10;
        if (n & 1) != 1 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }
        if ((n >> 16) & 1) != 1 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }
        if ((n >> 32) & 1) != 1 {
            return Err(Error::invalid_input("Unexpected marker bit"));
        }

        let n0 = (n >> 1) & ((1 << 15) - 1);
        let n1 = (n >> 17) & ((1 << 15) - 1);
        let n2 = (n >> 33) & ((1 << 3) - 1);
        let base = n0 | (n1 << 15) | (n2 << 30);
        Ok(ClockReference(base * 300 + extension))
    }

    pub(crate) fn write_escr_to<W: Write>(&self, mut writer: W) -> Result<()> {
        let base = self.0 / 300;
        let extension = self.0 % 300;

        let marker = 1;
        let base0 = base & ((1 << 15) - 1);
        let base1 = (base >> 15) & ((1 << 15) - 1);
        let base2 = base >> 30;

        let n = marker
            | (extension << 1)
            | (marker << 10)
            | (base0 << 11)
            | (marker << 26)
            | (base1 << 27)
            | (marker << 42)
            | (base2 << 43);
        writer.write_uint::<6>(n)?;
        Ok(())
    }
}
impl From<u32> for ClockReference {
    fn from(n: u32) -> Self {
        ClockReference(u64::from(n))
    }
}
impl From<Timestamp> for ClockReference {
    fn from(f: Timestamp) -> Self {
        ClockReference(f.0 * 300)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pcr_conversion() {
        let cr = ClockReference::new(10000).unwrap();
        let mut buf = Vec::new();
        cr.write_pcr_to(&mut buf).unwrap();
        let new_cr = ClockReference::read_pcr_from(&buf[..]).unwrap();
        assert_eq!(cr, new_cr);
    }

    #[test]
    fn pcr_bytes_layout() {
        let cr = ClockReference::new((0x1234567 << 1) * 300 + 5).unwrap();
        let bytes = cr.pcr_to_bytes();
        assert_eq!(bytes.len(), 6);
        assert_eq!(bytes[4] & 0x7E, 0x7E, "reserved bits must be '111111'");
        assert_eq!(
            ClockReference::read_pcr_from(&bytes[..]).unwrap(),
            cr,
            "pcr_to_bytes must round-trip through read_pcr_from"
        );
    }

    #[test]
    fn escr_conversion() {
        let cr = ClockReference::new(10000).unwrap();
        let mut buf = Vec::new();
        cr.write_escr_to(&mut buf).unwrap();
        let new_cr = ClockReference::read_escr_from(&buf[..]).unwrap();
        assert_eq!(cr, new_cr);
    }
}
