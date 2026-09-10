//! USB redirection (MS-RDPEUSB/URBDRC) backend.
//!
//! Accepts USB devices the Windows client offers for redirection: every
//! announced device is enumerated (instance ID, HW/compat IDs, capabilities)
//! and logged, so a plugged-in USB stick shows up on the LinRDP side. Actual
//! device I/O (descriptors, endpoints, transfers) requires a USB host stack
//! bound to physical hardware and is the desktop-integration follow-up; the
//! factory below keeps the channel fully negotiated end-to-end.

use ironrdp_server::{
    DeviceFactory, RdpUsbDeviceAnnounceInfo, UsbRedirDevice,
};

/// A redirected USB device: logs its announcement and lifecycle.
#[derive(Debug, Default)]
pub(crate) struct LoggingUsbDevice {
    instance_id: Option<String>,
}

impl UsbRedirDevice for LoggingUsbDevice {
    fn device_added(&mut self, info: RdpUsbDeviceAnnounceInfo) {
        self.instance_id = Some(info.announce.device_instance_id.clone());
        tracing::info!(
            device = %info.announce.device_instance_id,
            hw_ids = ?info.announce.hw_ids,
            compat_ids = ?info.announce.compat_ids,
            "USB device redirected from client"
        );
    }

    fn device_text(&mut self, text: ironrdp_server::DeviceText) {
        tracing::info!(?text, "USB device text from client");
    }

    fn close(&mut self) {
        if let Some(id) = &self.instance_id {
            tracing::info!(device = %id, "USB device redirection closed");
        }
    }
}

/// Factory handing a [`LoggingUsbDevice`] to every newly opened device channel.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct LoggingUsbDeviceFactory;

impl DeviceFactory for LoggingUsbDeviceFactory {
    fn create_device(&mut self) -> Option<Box<dyn UsbRedirDevice>> {
        Some(Box::new(LoggingUsbDevice::default()))
    }
}
