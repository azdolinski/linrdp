use ironrdp_core::{decode, impl_as_any};
use ironrdp_dvc::{DvcMessage, DvcProcessor, DvcServerProcessor};
use ironrdp_pdu::{PduResult, decode_err};
use tracing::{debug, warn};

use crate::CHANNEL_NAME;
use crate::pdu::{DisplayControlCapabilities, DisplayControlMonitorLayout, DisplayControlPdu};

pub trait DisplayControlHandler: Send {
    fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
        debug!(?layout);
    }
}

/// A server for the Display Control Virtual Channel.
pub struct DisplayControlServer {
    handler: Box<dyn DisplayControlHandler>,
    capabilities: DisplayControlCapabilities,
}

impl DisplayControlServer {
    /// Create a new DisplayControlServer that advertises one monitor of up to
    /// 3840 x 2400 pixels.
    pub fn new(handler: Box<dyn DisplayControlHandler>) -> Self {
        Self {
            handler,
            capabilities: DisplayControlCapabilities::server_default(),
        }
    }

    /// Advertise `capabilities` instead (MS-RDPEDISP 2.2.2.1). Layouts the
    /// client sends are held to them.
    #[must_use]
    pub fn with_capabilities(mut self, capabilities: DisplayControlCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
}

impl_as_any!(DisplayControlServer);

impl DvcProcessor for DisplayControlServer {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        let pdu = DisplayControlPdu::from(self.capabilities.clone());

        Ok(vec![Box::new(pdu)])
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        // MS-RDPEDISP 1.3: a configuration that "is invalid" is simply not
        // applied. That includes one the decoder already refuses, such as an
        // odd monitor width: it must not end the session.
        let pdu = match decode(payload) {
            Ok(pdu) => pdu,
            Err(error) => {
                warn!(error = %decode_err!(error), "Ignoring a display control PDU that does not decode");
                return Ok(Vec::new());
            }
        };

        match pdu {
            DisplayControlPdu::MonitorLayout(layout) => match validate_layout(&layout, &self.capabilities) {
                Ok(()) => self.handler.monitor_layout(layout),
                Err(reason) => warn!(?reason, ?layout, "Ignoring a monitor layout the server cannot apply"),
            },
            DisplayControlPdu::Caps(caps) => {
                debug!(?caps);
            }
        }
        Ok(Vec::new())
    }
}

impl DvcServerProcessor for DisplayControlServer {}

/// Why a monitor layout cannot be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidLayout {
    /// No monitor at all.
    NoMonitors,
    /// More monitors than `MaxNumMonitors` (MS-RDPEDISP 2.2.2.2).
    TooManyMonitors,
    /// Not exactly one monitor is flagged primary.
    NotOnePrimary,
    /// The primary monitor's upper-left corner is not (0, 0) (2.2.2.2.1).
    PrimaryNotAtOrigin,
    /// A width outside 200..=8192 or odd, or a height outside 200..=8192
    /// (2.2.2.2.1).
    MonitorSize,
    /// The monitors cover more than the advertised maximum area (2.2.2.2).
    AreaTooLarge,
    /// Two monitors overlap (3.1.5.2).
    Overlap,
    /// A monitor touches no other one, not even at a corner (3.1.5.2).
    Detached,
}

/// Check a client's layout the way MS-RDPEDISP 3.1.5.2 asks before the server
/// applies it: all fields "valid, consistent and within range" — including
/// the limits of `capabilities` the client was sent — no two monitors
/// overlapping, and each monitor "adjacent to at least one other monitor
/// (even if only at a single point)".
pub fn validate_layout(
    layout: &DisplayControlMonitorLayout,
    capabilities: &DisplayControlCapabilities,
) -> Result<(), InvalidLayout> {
    let monitors = layout.monitors();
    if monitors.is_empty() {
        return Err(InvalidLayout::NoMonitors);
    }
    if u32::try_from(monitors.len()).map_or(true, |count| count > capabilities.max_num_monitors()) {
        return Err(InvalidLayout::TooManyMonitors);
    }
    if monitors.iter().filter(|monitor| monitor.is_primary()).count() != 1 {
        return Err(InvalidLayout::NotOnePrimary);
    }

    let mut area: u64 = 0;
    let mut rects = Vec::with_capacity(monitors.len());
    for monitor in monitors {
        // `position` is `None` for a primary monitor away from (0, 0).
        let (left, top) = monitor.position().ok_or(InvalidLayout::PrimaryNotAtOrigin)?;
        let (width, height) = monitor.dimensions();
        if !(200..=8192).contains(&width) || !width.is_multiple_of(2) || !(200..=8192).contains(&height) {
            return Err(InvalidLayout::MonitorSize);
        }
        area = area.saturating_add(u64::from(width).saturating_mul(u64::from(height)));
        rects.push(Rect {
            left: i64::from(left),
            top: i64::from(top),
            right: i64::from(left).saturating_add(i64::from(width)),
            bottom: i64::from(top).saturating_add(i64::from(height)),
        });
    }
    if area > capabilities.max_monitor_area() {
        return Err(InvalidLayout::AreaTooLarge);
    }

    for (index, rect) in rects.iter().enumerate() {
        let mut others = rects
            .iter()
            .enumerate()
            .filter(|(other_index, _)| *other_index != index)
            .map(|(_, other)| other);
        if others.clone().any(|other| rect.overlaps(other)) {
            return Err(InvalidLayout::Overlap);
        }
        if rects.len() > 1 && !others.any(|other| rect.touches(other)) {
            return Err(InvalidLayout::Detached);
        }
    }

    Ok(())
}

/// A monitor's pixels: `left..right` by `top..bottom`.
struct Rect {
    left: i64,
    top: i64,
    right: i64,
    bottom: i64,
}

impl Rect {
    /// Whether the two share any pixel.
    fn overlaps(&self, other: &Self) -> bool {
        self.left < other.right && other.left < self.right && self.top < other.bottom && other.top < self.bottom
    }

    /// Whether the two share any point of their outlines, a corner included.
    fn touches(&self, other: &Self) -> bool {
        self.left <= other.right && other.left <= self.right && self.top <= other.bottom && other.top <= self.bottom
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pdu::MonitorLayoutEntry;

    fn caps(monitors: u32, width: u32, height: u32) -> DisplayControlCapabilities {
        DisplayControlCapabilities::new(monitors, width, height).expect("caps")
    }

    fn primary(width: u32, height: u32) -> MonitorLayoutEntry {
        MonitorLayoutEntry::new_primary(width, height).expect("primary")
    }

    fn secondary(width: u32, height: u32, left: i32, top: i32) -> MonitorLayoutEntry {
        MonitorLayoutEntry::new_secondary(width, height)
            .expect("secondary")
            .with_position(left, top)
            .expect("position")
    }

    fn check(monitors: &[MonitorLayoutEntry], capabilities: &DisplayControlCapabilities) -> Result<(), InvalidLayout> {
        let layout = DisplayControlMonitorLayout::new(monitors).expect("layout");
        validate_layout(&layout, capabilities)
    }

    #[test]
    fn a_single_primary_within_the_advertised_area_is_valid() {
        assert_eq!(check(&[primary(3840, 2160)], &caps(1, 3840, 2160)), Ok(()));
        assert_eq!(check(&[primary(1920, 1080)], &caps(1, 3840, 2160)), Ok(()));
    }

    /// MS-RDPEDISP 2.2.2.2: the layout's area "MUST NOT exceed the maximum
    /// monitor area defined by the server".
    #[test]
    fn a_layout_larger_than_the_advertised_area_is_refused() {
        assert_eq!(
            check(&[primary(4096, 2160)], &caps(1, 3840, 2160)),
            Err(InvalidLayout::AreaTooLarge)
        );
    }

    /// 2.2.2.2: at most MaxNumMonitors monitor definitions.
    #[test]
    fn more_monitors_than_advertised_are_refused() {
        let layout = [primary(1920, 1080), secondary(1920, 1080, 1920, 0)];

        assert_eq!(
            check(&layout, &caps(1, 3840, 2160)),
            Err(InvalidLayout::TooManyMonitors)
        );
        assert_eq!(check(&layout, &caps(2, 3840, 2160)), Ok(()));
    }

    /// 3.1.5.2: no two monitors overlap, and each touches another, if only
    /// at a corner.
    #[test]
    fn overlapping_or_detached_monitors_are_refused() {
        let caps = caps(3, 3840, 2160);

        assert_eq!(
            check(&[primary(1920, 1080), secondary(1920, 1080, 1000, 0)], &caps),
            Err(InvalidLayout::Overlap)
        );
        assert_eq!(
            check(&[primary(1920, 1080), secondary(1920, 1080, 2000, 0)], &caps),
            Err(InvalidLayout::Detached)
        );
        assert_eq!(
            check(&[primary(1920, 1080), secondary(1920, 1080, 1920, 1080)], &caps),
            Ok(()),
            "touching at a single point is adjacent"
        );
    }

    /// A layout as the client sends it, with the Flags of each monitor
    /// replaced: decoding, unlike `DisplayControlMonitorLayout::new`, does not
    /// check the primary monitor.
    fn decoded_with_flags(monitors: &[MonitorLayoutEntry], flags: &[u32]) -> DisplayControlMonitorLayout {
        let mut bytes = ironrdp_core::encode_vec(&DisplayControlPdu::MonitorLayout(
            DisplayControlMonitorLayout::new(monitors).expect("layout"),
        ))
        .expect("encode");
        for (index, flag) in flags.iter().enumerate() {
            // Header (8) + MonitorLayoutSize (4) + NumMonitors (4), then 40
            // bytes per monitor starting with its Flags.
            let at = 16 + 40 * index;
            bytes[at..at + 4].copy_from_slice(&flag.to_le_bytes());
        }
        match decode::<DisplayControlPdu>(&bytes).expect("decode") {
            DisplayControlPdu::MonitorLayout(layout) => layout,
            DisplayControlPdu::Caps(_) => panic!("a monitor layout"),
        }
    }

    /// MS-RDPEDISP 2.2.2.2.1: coordinates are relative to "the monitor
    /// designated as the primary display monitor", whose upper-left corner
    /// "is always (0, 0)".
    #[test]
    fn a_layout_without_exactly_one_primary_is_refused() {
        let caps = caps(2, 3840, 2160);
        let pair = [primary(1920, 1080), secondary(1920, 1080, 1920, 0)];

        let two_primaries = decoded_with_flags(&pair, &[1, 1]);
        assert_eq!(
            validate_layout(&two_primaries, &caps),
            Err(InvalidLayout::NotOnePrimary)
        );

        let no_primary = decoded_with_flags(&pair, &[0, 0]);
        assert_eq!(validate_layout(&no_primary, &caps), Err(InvalidLayout::NotOnePrimary));

        let primary_on_the_right = decoded_with_flags(&pair, &[0, 1]);
        assert_eq!(
            validate_layout(&primary_on_the_right, &caps),
            Err(InvalidLayout::PrimaryNotAtOrigin)
        );
    }

    /// MS-RDPEDISP 1.3: an invalid configuration is not applied, and that is
    /// all. A layout the decoder refuses (an odd width violates 2.2.2.2.1)
    /// used to fail the channel and with it the session.
    #[test]
    fn a_layout_that_does_not_decode_is_ignored() {
        struct Refuse;
        impl DisplayControlHandler for Refuse {
            fn monitor_layout(&self, layout: DisplayControlMonitorLayout) {
                panic!("an invalid layout reached the handler: {layout:?}");
            }
        }

        let mut bytes = ironrdp_core::encode_vec(&DisplayControlPdu::MonitorLayout(
            DisplayControlMonitorLayout::new(&[primary(1920, 1080)]).expect("layout"),
        ))
        .expect("encode");
        // Header (8) + MonitorLayoutSize (4) + NumMonitors (4) + Flags, Left,
        // Top (12): Width.
        bytes[28..32].copy_from_slice(&1921u32.to_le_bytes());

        let mut server = DisplayControlServer::new(Box::new(Refuse));
        assert!(server.process(0, &bytes).expect("not an error").is_empty());
    }
}
