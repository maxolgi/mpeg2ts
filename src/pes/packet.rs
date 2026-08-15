use crate::es::StreamId;
use crate::time::{ClockReference, Timestamp};
use crate::util::{ReadBytesExt, WriteBytesExt};
use crate::{Error, Result};
use std::io::{Read, Write};

const PACKET_START_CODE_PREFIX: u64 = 0x00_0001;

/// PES packet.
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct PesPacket<B> {
    pub header: PesHeader,
    pub data: B,
}

/// PES packet header.
///
/// Note that `PesHeader` contains the fields that belong to the optional PES header.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PesHeader {
    pub stream_id: StreamId,
    pub priority: bool,

    /// `true` indicates that the PES packet header is immediately followed by
    /// the video start code or audio syncword.
    pub data_alignment_indicator: bool,

    /// `true` implies copyrighted.
    pub copyright: bool,

    /// `true` implies original.
    pub original_or_copy: bool,

    pub pts: Option<Timestamp>,
    pub dts: Option<Timestamp>,

    /// Elementary stream clock reference.
    pub escr: Option<ClockReference>,
}
impl PesHeader {
    pub(super) fn optional_header_len(&self) -> u16 {
        3 + self.pts.map_or(0, |_| 5) + self.dts.map_or(0, |_| 5) + self.escr.map_or(0, |_| 6)
    }

    /// Calculates the length in bytes of the elementary stream payload carried
    /// by a PES packet that has this header.
    ///
    /// Per ISO/IEC 13818-1, `PES_packet_length` is the 16-bit field following
    /// the `stream_id` in the PES header, and it specifies the number of bytes
    /// in the PES packet **following the final byte of the field itself** —
    /// i.e., it counts both the optional PES header *and* the ES payload.
    /// The ES payload length is therefore `pes_packet_len` reduced by the
    /// optional header length (`optional_header_len()`).
    ///
    /// A `pes_packet_len` of `0` means the PES packet length is unbounded
    /// (only permitted for video elementary streams in transport streams),
    /// in which case `Ok(None)` is returned.
    ///
    /// # Errors
    ///
    /// If `pes_packet_len` is nonzero but smaller than the optional header
    /// length, the PES packet is malformed and an `ErrorKind::InvalidInput`
    /// error is returned.
    pub fn es_payload_len(&self, pes_packet_len: u16) -> Result<Option<usize>> {
        if pes_packet_len == 0 {
            return Ok(None);
        }
        let optional_header_len = self.optional_header_len();
        if pes_packet_len < optional_header_len {
            return Err(Error::invalid_input(format!(
                "pes.pes_packet_len={}, optional_header_len={}",
                pes_packet_len, optional_header_len
            )));
        }
        Ok(Some((pes_packet_len - optional_header_len) as usize))
    }

    pub(crate) fn read_from<R: Read>(mut reader: R) -> Result<(Self, u16)> {
        let packet_start_code_prefix = reader.read_uint::<3>()?;
        if packet_start_code_prefix != PACKET_START_CODE_PREFIX {
            return Err(Error::invalid_input(format!(
                "Expected packet start code prefix 0x{:06x}, got 0x{:06x}",
                PACKET_START_CODE_PREFIX, packet_start_code_prefix
            )));
        }

        let stream_id = StreamId::new(reader.read_u8()?);
        let packet_len = reader.read_u16()?;

        if stream_id.as_u8() == StreamId::PROGRAM_STREAM_MAP
            || stream_id.as_u8() == StreamId::PADDING_STREAM
            || stream_id.as_u8() == StreamId::PRIVATE_STREAM_2
            || stream_id.as_u8() == StreamId::ECM_STREAM
            || stream_id.as_u8() == StreamId::EMM_STREAM
            || stream_id.as_u8() == StreamId::PROGRAM_STREAM_DIRECTORY
            || stream_id.as_u8() == StreamId::DSM_CC
            || stream_id.as_u8() == StreamId::H222_1_TYPE_E
        {
            let header = PesHeader {
                stream_id,
                priority: false,
                data_alignment_indicator: false,
                copyright: false,
                original_or_copy: false,
                pts: None,
                dts: None,
                escr: None,
            };
            return Ok((header, packet_len));
        }

        let b = reader.read_u8()?;
        if (b & 0b1100_0000) != 0b1000_0000 {
            return Err(Error::invalid_input("Unexpected marker bits"));
        }
        let scrambling_control = (b & 0b0011_0000) >> 4;
        let priority = (b & 0b0000_1000) != 0;
        let data_alignment_indicator = (b & 0b0000_0100) != 0;
        let copyright = (b & 0b0000_0010) != 0;
        let original_or_copy = (b & 0b0000_0001) != 0;
        if scrambling_control != 0 {
            return Err(Error::unsupported("Scrambling control is not supported"));
        }

        let b = reader.read_u8()?;
        let pts_flag = (b & 0b1000_0000) != 0;
        let dts_flag = (b & 0b0100_0000) != 0;
        if !pts_flag && dts_flag {
            return Err(Error::invalid_input("DTS cannot be present without PTS"));
        }

        let escr_flag = (b & 0b0010_0000) != 0;
        let es_rate_flag = (b & 0b0001_0000) != 0;
        let dsm_trick_mode_flag = (b & 0b0000_1000) != 0;
        let additional_copy_info_flag = (b & 0b0000_0100) != 0;
        let crc_flag = (b & 0b0000_0010) != 0;
        let extension_flag = (b & 0b0000_0001) != 0;

        if es_rate_flag {
            return Err(Error::unsupported("ES rate flag is not supported"));
        }
        if dsm_trick_mode_flag {
            return Err(Error::unsupported("DSM trick mode flag is not supported"));
        }
        if additional_copy_info_flag {
            return Err(Error::unsupported(
                "Additional copy info flag is not supported",
            ));
        }
        if crc_flag {
            return Err(Error::unsupported("CRC flag is not supported"));
        }
        if extension_flag {
            return Err(Error::unsupported("Extension flag is not supported"));
        }

        let pes_header_len = reader.read_u8()?;

        let mut reader = reader.take(u64::from(pes_header_len));
        let pts = if pts_flag {
            let check_bits = if dts_flag { 3 } else { 2 };
            Some(Timestamp::read_from(&mut reader, check_bits)?)
        } else {
            None
        };
        let dts = if dts_flag {
            let check_bits = 1;
            Some(Timestamp::read_from(&mut reader, check_bits)?)
        } else {
            None
        };
        let escr = if escr_flag {
            Some(ClockReference::read_escr_from(&mut reader)?)
        } else {
            None
        };
        crate::util::consume_stuffing_bytes(reader)?;

        let header = PesHeader {
            stream_id,
            priority,
            data_alignment_indicator,
            copyright,
            original_or_copy,
            pts,
            dts,
            escr,
        };
        Ok((header, packet_len))
    }

    pub(crate) fn write_to<W: Write>(&self, mut writer: W, pes_header_len: u16) -> Result<()> {
        writer.write_uint::<3>(PACKET_START_CODE_PREFIX)?;
        writer.write_u8(self.stream_id.as_u8())?;
        writer.write_u16(pes_header_len)?;

        if self.stream_id.as_u8() == StreamId::PROGRAM_STREAM_MAP
            || self.stream_id.as_u8() == StreamId::PADDING_STREAM
            || self.stream_id.as_u8() == StreamId::PRIVATE_STREAM_2
            || self.stream_id.as_u8() == StreamId::ECM_STREAM
            || self.stream_id.as_u8() == StreamId::EMM_STREAM
            || self.stream_id.as_u8() == StreamId::PROGRAM_STREAM_DIRECTORY
            || self.stream_id.as_u8() == StreamId::DSM_CC
            || self.stream_id.as_u8() == StreamId::H222_1_TYPE_E
        {
            return Ok(());
        }

        let n = 0b1000_0000
            | ((self.priority as u8) << 3)
            | ((self.data_alignment_indicator as u8) << 2)
            | ((self.copyright as u8) << 1)
            | self.original_or_copy as u8;
        writer.write_u8(n)?;

        if self.dts.is_some() && self.pts.is_none() {
            return Err(Error::invalid_input("DTS cannot be present without PTS"));
        }
        let n = ((self.pts.is_some() as u8) << 7)
            | ((self.dts.is_some() as u8) << 6)
            | ((self.escr.is_some() as u8) << 5);
        writer.write_u8(n)?;

        let pes_header_len = self.optional_header_len() as u8 - 3;
        writer.write_u8(pes_header_len)?;
        if let Some(x) = self.pts {
            let check_bits = if self.dts.is_some() { 3 } else { 2 };
            x.write_to(&mut writer, check_bits)?;
        }
        if let Some(x) = self.dts {
            let check_bits = 1;
            x.write_to(&mut writer, check_bits)?;
        }
        if let Some(x) = self.escr {
            x.write_escr_to(&mut writer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ErrorKind;

    fn make_header(pts: Option<u64>, dts: Option<u64>, escr: Option<u64>) -> PesHeader {
        PesHeader {
            stream_id: StreamId::new_audio(StreamId::AUDIO_MIN).unwrap(),
            priority: false,
            data_alignment_indicator: false,
            copyright: false,
            original_or_copy: false,
            pts: pts.map(|n| Timestamp::new(n).unwrap()),
            dts: dts.map(|n| Timestamp::new(n).unwrap()),
            escr: escr.map(|n| ClockReference::new(n).unwrap()),
        }
    }

    #[test]
    fn es_payload_len_pts_only() {
        // Audio-style PES: optional header = 3 + 5 (PTS) = 8 bytes.
        let header = make_header(Some(0), None, None);
        assert_eq!(header.es_payload_len(3 + 5 + 100).unwrap(), Some(100));
        assert_eq!(header.es_payload_len(3 + 5).unwrap(), Some(0));
    }

    #[test]
    fn es_payload_len_pts_dts() {
        // Optional header = 3 + 5 (PTS) + 5 (DTS) = 13 bytes.
        let header = make_header(Some(0), Some(90_000), None);
        assert_eq!(header.es_payload_len(3 + 5 + 5 + 7).unwrap(), Some(7));
    }

    #[test]
    fn es_payload_len_escr() {
        // Optional header = 3 + 6 (ESCR) = 9 bytes, or 3 + 5 + 6 = 14 with PTS.
        let header = make_header(None, None, Some(0));
        assert_eq!(header.es_payload_len(3 + 6 + 21).unwrap(), Some(21));
        let header = make_header(Some(0), None, Some(0));
        assert_eq!(header.es_payload_len(3 + 5 + 6 + 21).unwrap(), Some(21));
    }

    #[test]
    fn es_payload_len_unbounded() {
        // A zero PES_packet_length means unbounded (e.g., video PES in TS).
        assert_eq!(
            make_header(Some(0), None, None).es_payload_len(0).unwrap(),
            None
        );
        assert_eq!(
            make_header(None, None, None).es_payload_len(0).unwrap(),
            None
        );
    }

    #[test]
    fn es_payload_len_too_small_pes_packet_len() {
        let header = make_header(Some(0), None, None); // optional header = 8 bytes
        let err = header.es_payload_len(7).unwrap_err();
        assert_eq!(err.kind, ErrorKind::InvalidInput);
        assert_eq!(err.reason, "pes.pes_packet_len=7, optional_header_len=8");
    }
}
