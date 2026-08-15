//! Continuity counter checking.
//!
//! See ISO/IEC 13818-1 (ITU-T Rec. H.222.0) §2.4.3.3 for the normative rules.

use crate::ts::{ContinuityCounter, Pid, TsPacket};
use std::collections::HashMap;

/// Result of a [`CcChecker::check`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CcStatus {
    /// The packet is consistent with the PID's continuity-counter sequence,
    /// or no sequence expectation applies to it (no payload, or the first
    /// packet seen on this PID).
    Ok,

    /// The packet breaks the continuity-counter sequence of its PID.
    Discontinuity {
        /// The counter value that was expected for this packet.
        expected: ContinuityCounter,

        /// The counter value the packet actually carried.
        got: ContinuityCounter,
    },

    /// The packet has `discontinuity_indicator` set in its adaptation field:
    /// a legitimate (signalled) reset of the PID's continuity-counter
    /// sequence. The checker has cleared its state for this PID; the next
    /// packet on the PID starts a new sequence.
    Reset,
}

/// Per-PID continuity counter checker.
///
/// Tracks the expected continuity counter of every PID seen so far and
/// reports violations of the rules defined in ISO/IEC 13818-1 §2.4.3.3.
///
/// Semantics and deliberate choices:
///
/// - Only packets that carry a payload (`adaptation_field_control` `0b01` or
///   `0b11`, i.e. `TsPacket::payload` is `Some`) advance the expectation;
///   packets without payload (`0b10`) leave the state untouched and return
///   [`CcStatus::Ok`]. (Note that a payload presence check is exactly
///   equivalent to `AdaptationFieldControl::has_payload()` — the reader only
///   sets `payload` for those values.)
/// - A packet whose adaptation field has `discontinuity_indicator` set returns
///   [`CcStatus::Reset`] and clears the PID's state — including when the PID
///   had no prior state. This is only signalled for payload-bearing packets,
///   matching the field's usual usage.
/// - The first payload-bearing packet seen on a PID initializes the sequence
///   and returns [`CcStatus::Ok`].
/// - **Duplicate packets** (same PID, same counter as the previous
///   payload-bearing packet) return [`CcStatus::Ok`]: §2.4.3.3 explicitly
///   permits a sender to repeat a packet (e.g. as a retransmission), so this
///   checker tolerates them rather than flagging a discontinuity.
/// - The counter of null packets (PID `0x1FFF`) is declared undefined by the
///   specification; this checker nevertheless tracks null packets like any
///   other PID, which matches streams that keep them sequential.
/// - `transport_error_indicator` is not treated specially.
#[derive(Debug, Default)]
pub struct CcChecker {
    last: HashMap<Pid, ContinuityCounter>,
}
impl CcChecker {
    /// Makes a new `CcChecker` instance.
    pub fn new() -> Self {
        CcChecker::default()
    }

    /// Checks the continuity counter of the given packet.
    ///
    /// The packet must already be parsed (e.g. by [`TsPacketReader`]); this
    /// crate performs no raw-byte parsing here. See the [type-level
    /// documentation][Self] for the exact semantics.
    ///
    /// [`TsPacketReader`]: crate::ts::TsPacketReader
    pub fn check(&mut self, packet: &TsPacket) -> CcStatus {
        if packet.payload.is_none() {
            return CcStatus::Ok;
        }
        let pid = packet.header.pid;
        let got = packet.header.continuity_counter;

        if packet
            .adaptation_field
            .as_ref()
            .is_some_and(|af| af.discontinuity_indicator)
        {
            self.last.remove(&pid);
            return CcStatus::Reset;
        }

        let Some(&last) = self.last.get(&pid) else {
            self.last.insert(pid, got);
            return CcStatus::Ok;
        };

        let mut expected = last;
        expected.increment();
        if got == last {
            // Legal duplicate packet (§2.4.3.3); tolerated by design.
            return CcStatus::Ok;
        }
        if got != expected {
            self.last.insert(pid, got);
            return CcStatus::Discontinuity { expected, got };
        }
        self.last.insert(pid, got);
        CcStatus::Ok
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ts::payload::Bytes;
    use crate::ts::{
        AdaptationField, ReadTsPacket, TransportScramblingControl, TsHeader, TsPacketReader,
        TsPayload,
    };

    fn header(pid: u16, cc: u8) -> TsHeader {
        TsHeader {
            transport_error_indicator: false,
            transport_priority: false,
            pid: Pid::new(pid).unwrap(),
            transport_scrambling_control: TransportScramblingControl::NotScrambled,
            continuity_counter: ContinuityCounter::from_u8(cc).unwrap(),
        }
    }

    fn adaptation_field(discontinuity_indicator: bool) -> AdaptationField {
        AdaptationField {
            discontinuity_indicator,
            random_access_indicator: false,
            es_priority_indicator: false,
            pcr: None,
            opcr: None,
            splice_countdown: None,
            transport_private_data: Vec::new(),
            extension: None,
        }
    }

    fn packet(
        pid: u16,
        cc: u8,
        adaptation_field: Option<AdaptationField>,
        with_payload: bool,
    ) -> TsPacket {
        TsPacket {
            header: header(pid, cc),
            adaptation_field,
            payload: with_payload.then(|| TsPayload::Raw(Bytes::new(&[]).unwrap())),
        }
    }

    // Builds a raw 188-byte TS packet. `af` bytes (length + first data byte)
    // are only meaningful for `afc` values that include an adaptation field.
    fn packet_bytes(pid: u16, cc: u8, afc: u8, af_len: u8, af_first: u8) -> [u8; 188] {
        let mut pkt = [0u8; 188];
        pkt[0] = 0x47;
        pkt[1] = ((pid >> 8) & 0x1F) as u8;
        pkt[2] = (pid & 0xFF) as u8;
        pkt[3] = (afc << 4) | (cc & 0x0F);
        pkt[4] = af_len;
        pkt[5] = af_first;
        pkt
    }

    fn read_packet(bytes: &[u8; 188]) -> TsPacket {
        TsPacketReader::new(&bytes[..])
            .read_ts_packet()
            .unwrap()
            .unwrap()
    }

    #[test]
    fn normal_increment_sequence_is_ok() {
        let mut checker = CcChecker::new();
        for cc in 0..5 {
            let status = checker.check(&packet(0x100, cc, None, true));
            assert_eq!(status, CcStatus::Ok);
        }
    }

    #[test]
    fn counter_wraps_from_15_to_0() {
        let mut checker = CcChecker::new();
        checker.check(&packet(0x100, 15, None, true));
        assert_eq!(checker.check(&packet(0x100, 0, None, true)), CcStatus::Ok);
    }

    #[test]
    fn packet_without_payload_does_not_advance() {
        let mut checker = CcChecker::new();
        checker.check(&packet(0x100, 0, None, true));
        // No-payload packet with a bogus counter must be ignored entirely.
        assert_eq!(
            checker.check(&packet(0x100, 9, Some(adaptation_field(false)), false)),
            CcStatus::Ok
        );
        assert_eq!(checker.check(&packet(0x100, 1, None, true)), CcStatus::Ok);
    }

    #[test]
    fn discontinuity_is_detected() {
        let mut checker = CcChecker::new();
        checker.check(&packet(0x100, 0, None, true));
        assert_eq!(
            checker.check(&packet(0x100, 2, None, true)),
            CcStatus::Discontinuity {
                expected: ContinuityCounter::from_u8(1).unwrap(),
                got: ContinuityCounter::from_u8(2).unwrap(),
            }
        );
        // State is re-seeded with the received counter.
        assert_eq!(checker.check(&packet(0x100, 3, None, true)), CcStatus::Ok);
    }

    #[test]
    fn discontinuity_indicator_resets_state() {
        let mut checker = CcChecker::new();
        checker.check(&packet(0x100, 0, None, true));
        assert_eq!(
            checker.check(&packet(0x100, 7, Some(adaptation_field(true)), true)),
            CcStatus::Reset
        );
        // Any counter is acceptable right after a signalled reset.
        assert_eq!(checker.check(&packet(0x100, 9, None, true)), CcStatus::Ok);
        assert_eq!(checker.check(&packet(0x100, 10, None, true)), CcStatus::Ok);

        // A signalled reset on a PID with no prior state is still a Reset.
        let mut checker = CcChecker::new();
        assert_eq!(
            checker.check(&packet(0x300, 4, Some(adaptation_field(true)), true)),
            CcStatus::Reset
        );
    }

    #[test]
    fn duplicate_packet_is_tolerated() {
        let mut checker = CcChecker::new();
        checker.check(&packet(0x100, 3, None, true));
        // Same counter twice: legal duplicate (e.g. retransmission).
        assert_eq!(checker.check(&packet(0x100, 3, None, true)), CcStatus::Ok);
        assert_eq!(checker.check(&packet(0x100, 4, None, true)), CcStatus::Ok);
    }

    #[test]
    fn first_packet_on_a_pid_initializes() {
        let mut checker = CcChecker::new();
        assert_eq!(checker.check(&packet(0x100, 13, None, true)), CcStatus::Ok);
        assert_eq!(checker.check(&packet(0x100, 14, None, true)), CcStatus::Ok);
    }

    #[test]
    fn pids_are_tracked_independently() {
        let mut checker = CcChecker::new();
        for cc in 0..3 {
            assert_eq!(checker.check(&packet(0x100, cc, None, true)), CcStatus::Ok);
            assert_eq!(checker.check(&packet(0x200, cc, None, true)), CcStatus::Ok);
        }
        assert!(matches!(
            checker.check(&packet(0x100, 7, None, true)),
            CcStatus::Discontinuity { .. }
        ));
        assert_eq!(checker.check(&packet(0x200, 3, None, true)), CcStatus::Ok);
    }

    #[test]
    fn zero_length_adaptation_field_payload_is_not_misread_as_flags() {
        // afc=0b11 with adaptation_field_length == 0 is legal single-byte
        // stuffing; byte 5 is then PAYLOAD. A payload byte with bit 7 set
        // must not be mistaken for the adaptation-field flags (in particular
        // for discontinuity_indicator).
        let mut checker = CcChecker::new();
        checker.check(&read_packet(&packet_bytes(0x100, 2, 0b01, 0, 0)));
        let suspect = read_packet(&packet_bytes(0x100, 3, 0b11, 0, 0x80));
        assert!(suspect.adaptation_field.is_none());
        assert!(suspect.payload.is_some());
        assert_eq!(checker.check(&suspect), CcStatus::Ok);
        // Tracking survived: the next real gap is still detected.
        assert_eq!(
            checker.check(&read_packet(&packet_bytes(0x100, 5, 0b01, 0, 0))),
            CcStatus::Discontinuity {
                expected: ContinuityCounter::from_u8(4).unwrap(),
                got: ContinuityCounter::from_u8(5).unwrap(),
            }
        );
    }

    #[test]
    fn discontinuity_indicator_via_reader_resets_state() {
        // adaptation_field_length == 1 carrying only the flags byte with
        // discontinuity_indicator set.
        let mut checker = CcChecker::new();
        checker.check(&read_packet(&packet_bytes(0x100, 0, 0b01, 0, 0)));
        let reset = read_packet(&packet_bytes(0x100, 1, 0b11, 1, 0x80));
        assert_eq!(
            reset
                .adaptation_field
                .as_ref()
                .unwrap()
                .discontinuity_indicator,
            true
        );
        assert_eq!(checker.check(&reset), CcStatus::Reset);
        assert_eq!(
            checker.check(&read_packet(&packet_bytes(0x100, 5, 0b01, 0, 0))),
            CcStatus::Ok
        );
    }
}
