//! Fitting a GNOME session's monitor to the RDP client.
//!
//! The GNOME case shows the session's own monitor, so the client gets whatever
//! resolution that monitor is in — 1280x800 on a VM console, into a client
//! window twice that size. linrdp switches the monitor to the mode that fits
//! the client best, through `org.gnome.Mutter.DisplayConfig`, and switches it
//! back when the client leaves. The switch is `temporary` (method 1): it is
//! never written to `monitors.xml`, so a crash cannot leave the desk at the
//! client's resolution for good.
//!
//! Only the simple layout is touched: one monitor in one logical monitor.
//! Anything else — two screens, mirroring — is somebody's deliberate layout,
//! and the client is shown the primary monitor as it is.

use std::collections::HashMap;

use anyhow::Context as _;
use zbus::Connection;
use zbus::zvariant::{OwnedValue, Value};

const NAME: &str = "org.gnome.Mutter.DisplayConfig";
const PATH: &str = "/org/gnome/Mutter/DisplayConfig";
const IFACE: &str = "org.gnome.Mutter.DisplayConfig";

/// `ApplyMonitorsConfig` method: apply now, do not persist.
const METHOD_TEMPORARY: u32 = 1;

/// One mode a monitor offers.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Mode {
    pub(crate) id: String,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) refresh: f64,
    pub(crate) current: bool,
}

/// The mode that fits a client of `want` best.
///
/// In order: the exact size (the current mode if it already is, else the
/// refresh rate nearest 60 Hz); otherwise the largest mode that fits inside
/// the client, closest in shape; otherwise — a client smaller than every mode
/// — the smallest mode, which the client then scales down least.
///
/// Pure: every monitor a machine can present is a test row.
pub(crate) fn best_mode(modes: &[Mode], want: (u32, u32)) -> Option<&Mode> {
    let (ww, wh) = want;
    let refresh_score = |m: &Mode| -((m.refresh - 60.0).abs());
    let exact = modes.iter().filter(|m| m.width == ww && m.height == wh);
    if let Some(current) = exact.clone().find(|m| m.current) {
        return Some(current);
    }
    if let Some(best) = exact.max_by(|a, b| refresh_score(a).total_cmp(&refresh_score(b))) {
        return Some(best);
    }
    let aspect = f64::from(ww.max(1)) / f64::from(wh.max(1));
    let shape = |m: &Mode| -((f64::from(m.width) / f64::from(m.height.max(1)) - aspect).abs());
    let fitting = modes.iter().filter(|m| m.width <= ww && m.height <= wh);
    if let Some(best) = fitting.max_by(|a, b| {
        (u64::from(a.width) * u64::from(a.height))
            .cmp(&(u64::from(b.width) * u64::from(b.height)))
            .then(shape(a).total_cmp(&shape(b)))
            .then(refresh_score(a).total_cmp(&refresh_score(b)))
    }) {
        return Some(best);
    }
    modes.iter().min_by_key(|m| u64::from(m.width) * u64::from(m.height))
}

type Serial = u32;
type MonitorId = (String, String, String, String);
type ModeInfo = (String, i32, i32, f64, f64, Vec<f64>, HashMap<String, OwnedValue>);
type MonitorInfo = (MonitorId, Vec<ModeInfo>, HashMap<String, OwnedValue>);
type LogicalInfo = (i32, i32, f64, u32, bool, Vec<MonitorId>, HashMap<String, OwnedValue>);
type State = (Serial, Vec<MonitorInfo>, Vec<LogicalInfo>, HashMap<String, OwnedValue>);

/// The one monitor of a simple layout, as it is now.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    serial: Serial,
    connector: String,
    scale: f64,
    transform: u32,
    pub(crate) modes: Vec<Mode>,
}

impl Layout {
    pub(crate) fn current(&self) -> Option<&Mode> {
        self.modes.iter().find(|m| m.current)
    }
}

/// Read the layout, or `None` when it is not the simple one-monitor layout.
pub(crate) async fn read(connection: &Connection) -> anyhow::Result<Option<Layout>> {
    let (serial, monitors, logical, _): State = connection
        .call_method(Some(NAME), PATH, Some(IFACE), "GetCurrentState", &())
        .await
        .context("DisplayConfig.GetCurrentState")?
        .body()
        .deserialize()?;
    let ([monitor], [logical]) = (monitors.as_slice(), logical.as_slice()) else {
        return Ok(None);
    };
    let ((connector, ..), mode_infos, _) = monitor;
    let (_, _, scale, transform, _, _, _) = logical;
    let modes = mode_infos
        .iter()
        .map(|(id, width, height, refresh, _, _, props)| Mode {
            id: id.clone(),
            width: width.unsigned_abs(),
            height: height.unsigned_abs(),
            refresh: *refresh,
            current: props
                .get("is-current")
                .and_then(|v| bool::try_from(v).ok())
                .unwrap_or(false),
        })
        .collect();
    Ok(Some(Layout {
        serial,
        connector: connector.clone(),
        scale: *scale,
        transform: *transform,
        modes,
    }))
}

/// Switch the monitor to `mode_id`, temporarily.
pub(crate) async fn apply(connection: &Connection, layout: &Layout, mode_id: &str) -> anyhow::Result<()> {
    let no_props: HashMap<&str, Value<'_>> = HashMap::new();
    let monitor = (layout.connector.as_str(), mode_id, no_props.clone());
    let logical = vec![(0i32, 0i32, layout.scale, layout.transform, true, vec![monitor])];
    let result = connection
        .call_method(
            Some(NAME),
            PATH,
            Some(IFACE),
            "ApplyMonitorsConfig",
            &(layout.serial, METHOD_TEMPORARY, logical, no_props.clone()),
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        // A fractional scale the new mode does not support: the mode matters
        // more than the scale, so retry at 1.
        Err(_) if layout.scale != 1.0 => {
            let monitor = (layout.connector.as_str(), mode_id, no_props.clone());
            let logical = vec![(0i32, 0i32, 1.0f64, layout.transform, true, vec![monitor])];
            connection
                .call_method(
                    Some(NAME),
                    PATH,
                    Some(IFACE),
                    "ApplyMonitorsConfig",
                    &(layout.serial, METHOD_TEMPORARY, logical, no_props),
                )
                .await
                .map(drop)
                .with_context(|| format!("DisplayConfig.ApplyMonitorsConfig({mode_id})"))
        }
        Err(error) => Err(anyhow::Error::new(error).context(format!("DisplayConfig.ApplyMonitorsConfig({mode_id})"))),
    }
}

/// Fit the monitor to a client of `want`. Returns the mode that was current
/// before, when this changed it — the one to go back to on disconnect.
pub(crate) async fn fit(connection: &Connection, want: (u32, u32)) -> anyhow::Result<Option<String>> {
    let Some(layout) = read(connection).await? else {
        tracing::info!("not a single-monitor layout — the client is shown the primary monitor as it is");
        return Ok(None);
    };
    let Some(best) = best_mode(&layout.modes, want) else {
        return Ok(None);
    };
    let previous = layout.current().map(|m| m.id.clone());
    if best.current {
        return Ok(None);
    }
    apply(connection, &layout, &best.id).await?;
    tracing::info!(
        client = format!("{}x{}", want.0, want.1),
        mode = best.id,
        was = previous.as_deref().unwrap_or("?"),
        "monitor switched to fit the client"
    );
    Ok(previous)
}

/// Put the monitor back in `mode_id`.
pub(crate) async fn restore(connection: &Connection, mode_id: &str) {
    match read(connection).await {
        Ok(Some(layout)) if layout.modes.iter().any(|m| m.id == mode_id) => {
            if layout.current().is_some_and(|m| m.id == mode_id) {
                return;
            }
            match apply(connection, &layout, mode_id).await {
                Ok(()) => tracing::info!(mode = mode_id, "monitor mode restored"),
                Err(error) => tracing::warn!(error = format!("{error:#}"), "could not restore the monitor mode"),
            }
        }
        Ok(_) => tracing::info!("the monitor layout changed meanwhile — leaving it as it is"),
        Err(error) => tracing::warn!(error = format!("{error:#}"), "could not read the monitor layout"),
    }
}

/// One logical monitor of a layout, with the mode each of its monitors is in.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Logical {
    x: i32,
    y: i32,
    scale: f64,
    transform: u32,
    primary: bool,
    /// (connector, mode id)
    monitors: Vec<(String, String)>,
}

/// A whole layout, to put back exactly as it was.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Snapshot {
    pub(crate) connectors: Vec<String>,
    logical: Vec<Logical>,
}

async fn state(connection: &Connection) -> anyhow::Result<State> {
    Ok(connection
        .call_method(Some(NAME), PATH, Some(IFACE), "GetCurrentState", &())
        .await
        .context("DisplayConfig.GetCurrentState")?
        .body()
        .deserialize()?)
}

fn current_mode(monitors: &[MonitorInfo], connector: &str) -> Option<String> {
    monitors
        .iter()
        .find(|((c, ..), _, _)| c == connector)?
        .1
        .iter()
        .find(|(.., props)| props.get("is-current").and_then(|v| bool::try_from(v).ok()).unwrap_or(false))
        .map(|(id, ..)| id.clone())
}

/// The layout as it is now.
pub(crate) async fn snapshot(connection: &Connection) -> anyhow::Result<Snapshot> {
    let (_, monitors, logical, _) = state(connection).await?;
    let connectors = monitors.iter().map(|((c, ..), _, _)| c.clone()).collect();
    let logical = logical
        .iter()
        .map(|(x, y, scale, transform, primary, ids, _)| Logical {
            x: *x,
            y: *y,
            scale: *scale,
            transform: *transform,
            primary: *primary,
            monitors: ids
                .iter()
                .filter_map(|(c, ..)| Some((c.clone(), current_mode(&monitors, c)?)))
                .collect(),
        })
        .collect();
    Ok(Snapshot { connectors, logical })
}

async fn apply_logical(connection: &Connection, serial: Serial, logical: &[Logical]) -> anyhow::Result<()> {
    let no_props: HashMap<&str, Value<'_>> = HashMap::new();
    let wire: Vec<_> = logical
        .iter()
        .map(|l| {
            (
                l.x,
                l.y,
                l.scale,
                l.transform,
                l.primary,
                l.monitors
                    .iter()
                    .map(|(c, m)| (c.as_str(), m.as_str(), no_props.clone()))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    connection
        .call_method(
            Some(NAME),
            PATH,
            Some(IFACE),
            "ApplyMonitorsConfig",
            &(serial, METHOD_TEMPORARY, wire, no_props.clone()),
        )
        .await
        .map(drop)
        .context("DisplayConfig.ApplyMonitorsConfig")
}

/// Make `connector` the only monitor of the layout, in the mode it is in —
/// the console shown at the client's size, with the desk's own monitors off.
pub(crate) async fn make_sole(connection: &Connection, connector: &str) -> anyhow::Result<()> {
    let (serial, monitors, _, _) = state(connection).await?;
    let mode = current_mode(&monitors, connector).with_context(|| format!("{connector} has no current mode"))?;
    let sole = Logical {
        x: 0,
        y: 0,
        scale: 1.0,
        transform: 0,
        primary: true,
        monitors: vec![(connector.to_owned(), mode)],
    };
    apply_logical(connection, serial, &[sole]).await
}

/// Put back a layout taken with [`snapshot`]. Monitors that have gone since
/// are left out; if none is left, nothing is applied.
pub(crate) async fn restore_snapshot(connection: &Connection, snapshot: &Snapshot) {
    let result = async {
        let (serial, monitors, _, _) = state(connection).await?;
        let present: Vec<&str> = monitors.iter().map(|((c, ..), _, _)| c.as_str()).collect();
        let logical: Vec<Logical> = snapshot
            .logical
            .iter()
            .filter(|l| l.monitors.iter().all(|(c, _)| present.contains(&c.as_str())))
            .cloned()
            .collect();
        anyhow::ensure!(!logical.is_empty(), "none of the monitors of the saved layout is present");
        apply_logical(connection, serial, &logical).await
    }
    .await;
    match result {
        Ok(()) => tracing::info!("the desk's monitor layout restored"),
        Err(error) => tracing::warn!(error = format!("{error:#}"), "could not restore the desk's monitor layout"),
    }
}

/// The connector that appeared since `before` — the virtual monitor a
/// `RecordVirtual` stream created.
pub(crate) async fn new_connector(connection: &Connection, before: &Snapshot) -> anyhow::Result<Option<String>> {
    let now = snapshot(connection).await?;
    Ok(now.connectors.into_iter().find(|c| !before.connectors.contains(c)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(width: u32, height: u32, refresh: f64, current: bool) -> Mode {
        Mode {
            id: format!("{width}x{height}@{refresh:.3}"),
            width,
            height,
            refresh,
            current,
        }
    }

    /// The monitor of the Proxmox VM this was built on.
    fn qemu() -> Vec<Mode> {
        vec![
            mode(2560, 1080, 50.0, false),
            mode(2048, 1152, 60.0, false),
            mode(1920, 1440, 60.0, false),
            mode(1920, 1200, 59.885, false),
            mode(1920, 1080, 60.0, false),
            mode(1920, 1080, 50.0, false),
            mode(1680, 1050, 59.954, false),
            mode(1440, 900, 59.887, false),
            mode(1280, 800, 74.994, true),
            mode(1024, 768, 60.004, false),
            mode(800, 600, 60.317, false),
        ]
    }

    #[test]
    fn an_exact_mode_is_taken_at_the_refresh_nearest_60() {
        assert_eq!(best_mode(&qemu(), (1920, 1080)).map(|m| m.id.as_str()), Some("1920x1080@60.000"));
    }

    #[test]
    fn the_current_mode_is_kept_when_it_already_fits_exactly() {
        let modes = qemu();
        assert!(best_mode(&modes, (1280, 800)).expect("mode").current);
    }

    /// A windowed client is rarely a monitor mode: the largest mode inside it
    /// wins, so nothing is ever cut off.
    #[test]
    fn an_odd_client_size_gets_the_largest_mode_inside_it() {
        // 1680x1050 would be 50 rows taller than the window.
        assert_eq!(best_mode(&qemu(), (1900, 1000)).map(|m| m.id.as_str()), Some("1440x900@59.887"));
        // Largest area first: 1920x1440 and 2560x1080 tie at 2 764 800
        // pixels, and the shape nearer 16:9 breaks the tie.
        assert_eq!(best_mode(&qemu(), (2560, 1440)).map(|m| m.id.as_str()), Some("1920x1440@60.000"));
    }

    #[test]
    fn a_client_smaller_than_every_mode_gets_the_smallest() {
        assert_eq!(best_mode(&qemu(), (640, 480)).map(|m| m.id.as_str()), Some("800x600@60.317"));
    }

    /// A real panel with one mode: nothing to switch to, nothing breaks.
    #[test]
    fn a_single_mode_monitor_stays_as_it_is() {
        let panel = vec![mode(1920, 1080, 60.0, true)];
        assert!(best_mode(&panel, (2560, 1440)).expect("mode").current);
        assert!(best_mode(&panel, (1280, 720)).expect("mode").current);
    }
}
