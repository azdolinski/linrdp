//! What `linrdp config` shows and what pressing a key does to it — with no
//! terminal anywhere in sight.
//!
//! The rule the rest of this crate follows applies here too: the value is
//! built first and drawn second, so the questions worth asking ("does the tree
//! list every key?", "does an override show what it inherits?") can be asked
//! of a plain function.
//!
//! The tree lists the *schema*, not the file. A key nobody has ever written is
//! in it, showing its default and marked as one — that is what makes this a
//! way to discover settings rather than only a way to change the ones you
//! already know about.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::config::meta;
use crate::config::{Auth, Config, DisplayRange, Listener, Size};

/// Every setting that lives in a global block, and may therefore also be
/// overridden on one listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Setting {
    DisplayRange,
    FixedSize,
    LockOnDisconnect,
    SwitchToGreeter,
    ConsoleEnabled,
    ConsoleDisplay,
    ConsoleXauthority,
    Usb,
    Udp,
    Avc444v2,
    Wayland,
    MaxWorkers,
    MaxPerClient,
    HandshakeSeconds,
    TlsCert,
    TlsKey,
    LogLevel,
    LogFile,
}

impl Setting {
    /// The metadata path — which is also the help text, the allowed values and
    /// the documented default.
    pub(crate) fn schema(self) -> &'static str {
        match self {
            Self::DisplayRange => "session.display_range",
            Self::FixedSize => "session.fixed_size",
            Self::LockOnDisconnect => "session.lock_on_disconnect",
            Self::SwitchToGreeter => "session.switch_to_greeter",
            Self::ConsoleEnabled => "session.console.enabled",
            Self::ConsoleDisplay => "session.console.display",
            Self::ConsoleXauthority => "session.console.xauthority",
            Self::Usb => "features.usb",
            Self::Udp => "features.udp",
            Self::Avc444v2 => "features.avc444v2",
            Self::Wayland => "features.wayland",
            Self::MaxWorkers => "limits.max_workers",
            Self::MaxPerClient => "limits.max_per_client",
            Self::HandshakeSeconds => "limits.handshake_seconds",
            Self::TlsCert => "tls.cert",
            Self::TlsKey => "tls.key",
            Self::LogLevel => "log.level",
            Self::LogFile => "log.file",
        }
    }

    /// Whether a listener may carry its own value for this key.
    pub(crate) fn overridable(self) -> bool {
        meta::override_refusal(self.schema()).is_none()
    }

    fn get(self, config: &Config) -> String {
        match self {
            Self::DisplayRange => config.session.display_range.to_string(),
            Self::FixedSize => opt(config.session.fixed_size.map(|s| s.to_string())),
            Self::LockOnDisconnect => config.session.lock_on_disconnect.to_string(),
            Self::SwitchToGreeter => config.session.switch_to_greeter.to_string(),
            Self::ConsoleEnabled => config.session.console.enabled.to_string(),
            Self::ConsoleDisplay => opt(config.session.console.display.clone()),
            Self::ConsoleXauthority => opt(path(config.session.console.xauthority.as_ref())),
            Self::Usb => config.features.usb.to_string(),
            Self::Udp => config.features.udp.to_string(),
            Self::Avc444v2 => config.features.avc444v2.to_string(),
            Self::Wayland => config.features.wayland.to_string(),
            Self::MaxWorkers => config.limits.max_workers.to_string(),
            Self::MaxPerClient => config.limits.max_per_client.to_string(),
            Self::HandshakeSeconds => config.limits.handshake_seconds.to_string(),
            Self::TlsCert => opt(path(config.tls.cert.as_ref())),
            Self::TlsKey => opt(path(config.tls.key.as_ref())),
            Self::LogLevel => config.log.level.clone(),
            Self::LogFile => opt(path(config.log.file.as_ref())),
        }
    }

    fn set(self, config: &mut Config, raw: &str) -> anyhow::Result<()> {
        match self {
            Self::DisplayRange => config.session.display_range = raw.parse::<DisplayRange>()?,
            Self::FixedSize => config.session.fixed_size = parse_opt::<Size>(raw)?,
            Self::LockOnDisconnect => config.session.lock_on_disconnect = parse_bool(raw)?,
            Self::SwitchToGreeter => config.session.switch_to_greeter = parse_bool(raw)?,
            Self::ConsoleEnabled => config.session.console.enabled = parse_bool(raw)?,
            Self::ConsoleDisplay => config.session.console.display = unset_or(raw),
            Self::ConsoleXauthority => config.session.console.xauthority = unset_or(raw).map(PathBuf::from),
            Self::Usb => config.features.usb = parse_bool(raw)?,
            Self::Udp => config.features.udp = parse_bool(raw)?,
            Self::Avc444v2 => config.features.avc444v2 = parse_bool(raw)?,
            Self::Wayland => config.features.wayland = parse_bool(raw)?,
            Self::MaxWorkers => config.limits.max_workers = parse_limit(raw, "limits.max_workers")?,
            Self::MaxPerClient => config.limits.max_per_client = parse_limit(raw, "limits.max_per_client")?,
            Self::HandshakeSeconds => {
                config.limits.handshake_seconds = parse_limit(raw, "limits.handshake_seconds")?;
            }
            Self::TlsCert => config.tls.cert = unset_or(raw).map(PathBuf::from),
            Self::TlsKey => config.tls.key = unset_or(raw).map(PathBuf::from),
            Self::LogLevel => config.log.level = raw.trim().to_owned(),
            Self::LogFile => config.log.file = unset_or(raw).map(PathBuf::from),
        }
        Ok(())
    }

    /// The value this listener overrides the key with, if it does.
    fn override_of(self, config: &Config, listener: usize) -> Option<String> {
        let overrides = config.listeners.get(listener)?.overrides.as_ref()?;
        match self {
            Self::FixedSize => overrides
                .session
                .as_ref()?
                .fixed_size
                .map(|size| opt(size.map(|s| s.to_string()))),
            Self::LockOnDisconnect => overrides.session.as_ref()?.lock_on_disconnect.map(|v| v.to_string()),
            Self::SwitchToGreeter => overrides.session.as_ref()?.switch_to_greeter.map(|v| v.to_string()),
            Self::ConsoleEnabled => overrides
                .session
                .as_ref()?
                .console
                .as_ref()?
                .enabled
                .map(|v| v.to_string()),
            Self::ConsoleDisplay => overrides.session.as_ref()?.console.as_ref()?.display.clone().map(opt),
            Self::ConsoleXauthority => overrides
                .session
                .as_ref()?
                .console
                .as_ref()?
                .xauthority
                .clone()
                .map(|value| opt(value.map(|p| p.display().to_string()))),
            Self::Usb => overrides.features.as_ref()?.usb.map(|v| v.to_string()),
            Self::Udp => overrides.features.as_ref()?.udp.map(|v| v.to_string()),
            Self::Avc444v2 => overrides.features.as_ref()?.avc444v2.map(|v| v.to_string()),
            Self::Wayland => overrides.features.as_ref()?.wayland.map(|v| v.to_string()),
            Self::TlsCert => overrides
                .tls
                .as_ref()?
                .cert
                .clone()
                .map(|value| opt(value.map(|p| p.display().to_string()))),
            Self::TlsKey => overrides
                .tls
                .as_ref()?
                .key
                .clone()
                .map(|value| opt(value.map(|p| p.display().to_string()))),
            // Never overridable; `overridable()` keeps these out of the tree.
            Self::DisplayRange
            | Self::LogLevel
            | Self::LogFile
            | Self::MaxWorkers
            | Self::MaxPerClient
            | Self::HandshakeSeconds => None,
        }
    }
}

/// Where a row's value lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Slot {
    Bind(usize),
    ListenerAuth(usize),
    Global(Setting),
    Override(usize, Setting),
}

impl Slot {
    pub(crate) fn schema(self) -> &'static str {
        match self {
            Self::Bind(_) => "listeners[].bind",
            Self::ListenerAuth(_) => "listeners[].auth",
            Self::Global(key) | Self::Override(_, key) => key.schema(),
        }
    }

    /// The value as written, with `null` for a key nobody has set.
    pub(crate) fn get(self, config: &Config) -> String {
        match self {
            Self::Bind(index) => config.listeners.get(index).map(|l| l.bind.clone()).unwrap_or_default(),
            Self::ListenerAuth(index) => config
                .listeners
                .get(index)
                .map_or_else(String::new, |l| l.auth.to_string()),
            Self::Global(key) => key.get(config),
            Self::Override(index, key) => key.override_of(config, index).unwrap_or_else(|| key.get(config)),
        }
    }

    /// Write `raw` here, refusing anything the file would then reject.
    pub(crate) fn set(self, config: &mut Config, raw: &str) -> anyhow::Result<()> {
        match self {
            Self::Bind(index) => {
                let bind = raw.trim().to_owned();
                anyhow::ensure!(
                    !config
                        .listeners
                        .iter()
                        .enumerate()
                        .any(|(n, l)| n != index && l.bind == bind),
                    "another listener is already bound to `{bind}`"
                );
                if let Some(listener) = config.listeners.get_mut(index) {
                    listener.bind = bind;
                }
            }
            Self::ListenerAuth(index) => {
                let auth = parse_auth(raw)?;
                if let Some(listener) = config.listeners.get_mut(index) {
                    listener.auth = auth;
                }
            }
            Self::Global(key) => key.set(config, raw)?,
            Self::Override(index, key) => set_override(config, index, key, Some(raw))?,
        }
        // Everything the file refuses, the editor refuses in place — so a
        // saved file is always one the service starts on.
        crate::config::validate(config)
    }

    /// Drop an override, so the listener inherits again. Only meaningful for
    /// [`Slot::Override`].
    pub(crate) fn clear(self, config: &mut Config) -> anyhow::Result<()> {
        if let Self::Override(index, key) = self {
            set_override(config, index, key, None)?;
        }
        crate::config::validate(config)
    }
}

/// Where a row's value comes from, which is what the marker column says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// Nobody set it; this is the built-in default.
    Default,
    /// Set in a global block.
    Set,
    /// This listener carries its own value.
    Overridden,
    /// Inherited from the global block, on a listener that could override it.
    Inherited,
    /// A heading.
    Branch,
}

/// One visible line of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) depth: usize,
    pub(crate) label: String,
    pub(crate) value: Option<String>,
    /// Metadata path, for the help pane.
    pub(crate) schema: &'static str,
    pub(crate) slot: Option<Slot>,
    pub(crate) source: Source,
    /// Identity for the collapse set; stable across redraws.
    pub(crate) id: String,
    pub(crate) expandable: bool,
    pub(crate) expanded: bool,
}

/// The whole editor: a configuration, what is folded away, and where the
/// cursor is.
#[derive(Debug, Clone)]
pub(crate) struct Model {
    pub(crate) config: Config,
    /// Branch ids the operator has folded. Absent means open, so a fresh
    /// screen shows everything there is.
    pub(crate) collapsed: BTreeSet<String>,
    pub(crate) cursor: usize,
    pub(crate) dirty: bool,
}

impl Model {
    pub(crate) fn new(config: Config) -> Self {
        // Overrides start folded: they are the exception, and a file without
        // any would otherwise open with one empty heading per listener.
        let collapsed = (0..config.listeners.len())
            .map(|index| format!("listeners[{index}].overrides"))
            .collect();
        Self {
            config,
            collapsed,
            cursor: 0,
            dirty: false,
        }
    }

    /// Every line currently on screen, top to bottom.
    pub(crate) fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        self.push_branch(&mut rows, 0, "listeners", "listeners".to_owned(), "listeners");
        if self.is_open("listeners") {
            for (index, listener) in self.config.listeners.iter().enumerate() {
                self.push_listener(&mut rows, index, listener);
            }
        }

        self.push_block(
            &mut rows,
            "session",
            &[
                Setting::DisplayRange,
                Setting::FixedSize,
                Setting::LockOnDisconnect,
                Setting::SwitchToGreeter,
            ],
        );
        if self.is_open("session") {
            self.push_branch(&mut rows, 1, "session.console", "console".to_owned(), "session.console");
            if self.is_open("session.console") {
                for key in [
                    Setting::ConsoleEnabled,
                    Setting::ConsoleDisplay,
                    Setting::ConsoleXauthority,
                ] {
                    rows.push(self.global_row(2, key));
                }
            }
        }

        self.push_block(
            &mut rows,
            "features",
            &[Setting::Usb, Setting::Udp, Setting::Avc444v2, Setting::Wayland],
        );
        self.push_block(
            &mut rows,
            "limits",
            &[Setting::MaxWorkers, Setting::MaxPerClient, Setting::HandshakeSeconds],
        );
        self.push_block(&mut rows, "tls", &[Setting::TlsCert, Setting::TlsKey]);
        self.push_block(&mut rows, "log", &[Setting::LogLevel, Setting::LogFile]);
        rows
    }

    pub(crate) fn selected(&self) -> Option<Row> {
        self.rows().into_iter().nth(self.cursor)
    }

    /// Keep the cursor on a line that exists — the tree shrinks when a branch
    /// folds or a listener is removed.
    pub(crate) fn clamp(&mut self) {
        let len = self.rows().len();
        self.cursor = self.cursor.min(len.saturating_sub(1));
    }

    pub(crate) fn toggle(&mut self, id: &str) {
        if !self.collapsed.remove(id) {
            self.collapsed.insert(id.to_owned());
        }
    }

    fn is_open(&self, id: &str) -> bool {
        !self.collapsed.contains(id)
    }

    fn push_branch(&self, rows: &mut Vec<Row>, depth: usize, schema: &'static str, label: String, id: &str) {
        rows.push(Row {
            depth,
            label,
            value: None,
            schema,
            slot: None,
            source: Source::Branch,
            id: id.to_owned(),
            expandable: true,
            expanded: self.is_open(id),
        });
    }

    fn push_block(&self, rows: &mut Vec<Row>, id: &'static str, keys: &[Setting]) {
        self.push_branch(rows, 0, id, id.to_owned(), id);
        if self.is_open(id) {
            for key in keys {
                rows.push(self.global_row(1, *key));
            }
        }
    }

    fn global_row(&self, depth: usize, key: Setting) -> Row {
        let schema = key.schema();
        let value = Slot::Global(key).get(&self.config);
        Row {
            depth,
            label: leaf_name(schema).to_owned(),
            value: Some(value.clone()),
            schema,
            slot: Some(Slot::Global(key)),
            source: if is_default(schema, &value) {
                Source::Default
            } else {
                Source::Set
            },
            id: schema.to_owned(),
            expandable: false,
            expanded: false,
        }
    }

    fn push_listener(&self, rows: &mut Vec<Row>, index: usize, listener: &Listener) {
        let id = format!("listeners[{index}]");
        rows.push(Row {
            depth: 1,
            label: listener.bind.clone(),
            value: Some(format!("auth: {}", listener.auth)),
            schema: "listeners[].bind",
            slot: None,
            source: Source::Branch,
            id: id.clone(),
            expandable: true,
            expanded: self.is_open(&id),
        });
        if !self.is_open(&id) {
            return;
        }

        for slot in [Slot::Bind(index), Slot::ListenerAuth(index)] {
            let schema = slot.schema();
            rows.push(Row {
                depth: 2,
                label: leaf_name(schema).to_owned(),
                value: Some(slot.get(&self.config)),
                schema,
                slot: Some(slot),
                source: Source::Set,
                id: format!("{id}.{}", leaf_name(schema)),
                expandable: false,
                expanded: false,
            });
        }

        let overrides_id = format!("{id}.overrides");
        self.push_branch(rows, 2, "listeners[].overrides", "overrides".to_owned(), &overrides_id);
        if !self.is_open(&overrides_id) {
            return;
        }
        for key in ALL_SETTINGS.iter().filter(|key| key.overridable()) {
            let slot = Slot::Override(index, *key);
            let overridden = key.override_of(&self.config, index);
            rows.push(Row {
                depth: 3,
                // The full path, because these rows are flat: `enabled` on its
                // own could be the console's or anything else's, whereas in
                // the global tree it sits under the heading that says.
                label: key.schema().to_owned(),
                value: Some(slot.get(&self.config)),
                schema: key.schema(),
                slot: Some(slot),
                source: if overridden.is_some() {
                    Source::Overridden
                } else {
                    Source::Inherited
                },
                id: format!("{overrides_id}.{}", leaf_name(key.schema())),
                expandable: false,
                expanded: false,
            });
        }
    }

    /// Add a listener, on the first free port above the highest configured one.
    pub(crate) fn add_listener(&mut self) -> anyhow::Result<()> {
        let next = self
            .config
            .listeners
            .iter()
            .filter_map(|l| l.bind.rsplit(':').next()?.parse::<u16>().ok())
            .max()
            .unwrap_or(3388)
            .saturating_add(1);
        self.config.listeners.push(Listener {
            bind: format!("0.0.0.0:{next}"),
            auth: Auth::Both,
            overrides: None,
        });
        self.dirty = true;
        crate::config::validate(&self.config)
    }

    /// Remove a listener. The last one may not go: a service that binds
    /// nothing accepts nothing, and the file would not load again.
    pub(crate) fn remove_listener(&mut self, index: usize) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.config.listeners.len() > 1,
            "this is the only listener — a service with none accepts nothing"
        );
        anyhow::ensure!(index < self.config.listeners.len(), "no such listener");
        self.config.listeners.remove(index);
        self.dirty = true;
        crate::config::validate(&self.config)
    }
}

/// Every global key, in the order the file writes them.
pub(crate) const ALL_SETTINGS: [Setting; 15] = [
    Setting::DisplayRange,
    Setting::FixedSize,
    Setting::LockOnDisconnect,
    Setting::SwitchToGreeter,
    Setting::ConsoleEnabled,
    Setting::ConsoleDisplay,
    Setting::ConsoleXauthority,
    Setting::Usb,
    Setting::Udp,
    Setting::Avc444v2,
    Setting::Wayland,
    Setting::TlsCert,
    Setting::TlsKey,
    Setting::LogLevel,
    Setting::LogFile,
];

fn set_override(config: &mut Config, index: usize, key: Setting, raw: Option<&str>) -> anyhow::Result<()> {
    anyhow::ensure!(
        key.overridable(),
        "{}",
        meta::override_refusal(key.schema()).unwrap_or("this key is service-wide")
    );
    let Some(listener) = config.listeners.get_mut(index) else {
        anyhow::bail!("no such listener");
    };
    let overrides = listener.overrides.get_or_insert_with(Default::default);

    match key {
        Setting::FixedSize => {
            let session = overrides.session.get_or_insert_with(Default::default);
            session.fixed_size = raw.map(parse_opt::<Size>).transpose()?;
        }
        Setting::LockOnDisconnect => {
            let session = overrides.session.get_or_insert_with(Default::default);
            session.lock_on_disconnect = raw.map(parse_bool).transpose()?;
        }
        Setting::SwitchToGreeter => {
            let session = overrides.session.get_or_insert_with(Default::default);
            session.switch_to_greeter = raw.map(parse_bool).transpose()?;
        }
        Setting::ConsoleEnabled => {
            let session = overrides.session.get_or_insert_with(Default::default);
            let console = session.console.get_or_insert_with(Default::default);
            console.enabled = raw.map(parse_bool).transpose()?;
        }
        Setting::ConsoleDisplay => {
            let session = overrides.session.get_or_insert_with(Default::default);
            let console = session.console.get_or_insert_with(Default::default);
            console.display = raw.map(unset_or);
        }
        Setting::ConsoleXauthority => {
            let session = overrides.session.get_or_insert_with(Default::default);
            let console = session.console.get_or_insert_with(Default::default);
            console.xauthority = raw.map(|value| unset_or(value).map(PathBuf::from));
        }
        Setting::Usb => {
            overrides.features.get_or_insert_with(Default::default).usb = raw.map(parse_bool).transpose()?
        }
        Setting::Udp => {
            overrides.features.get_or_insert_with(Default::default).udp = raw.map(parse_bool).transpose()?
        }
        Setting::Avc444v2 => {
            overrides.features.get_or_insert_with(Default::default).avc444v2 = raw.map(parse_bool).transpose()?;
        }
        Setting::Wayland => {
            overrides.features.get_or_insert_with(Default::default).wayland = raw.map(parse_bool).transpose()?;
        }
        Setting::TlsCert => {
            overrides.tls.get_or_insert_with(Default::default).cert =
                raw.map(|value| unset_or(value).map(PathBuf::from));
        }
        Setting::TlsKey => {
            overrides.tls.get_or_insert_with(Default::default).key =
                raw.map(|value| unset_or(value).map(PathBuf::from));
        }
        Setting::DisplayRange
        | Setting::LogLevel
        | Setting::LogFile
        | Setting::MaxWorkers
        | Setting::MaxPerClient
        | Setting::HandshakeSeconds => {
            anyhow::bail!("{}", meta::override_refusal(key.schema()).unwrap_or("service-wide"))
        }
    }

    // An override block emptied by the last `clear` is dropped, so the file
    // does not accumulate `overrides: {}` where somebody once changed a key
    // back.
    if let Some(listener) = config.listeners.get_mut(index) {
        if listener.overrides.as_ref().is_some_and(is_empty_override) {
            listener.overrides = None;
        }
    }
    Ok(())
}

fn is_empty_override(overrides: &crate::config::Overrides) -> bool {
    let session_empty = overrides.session.as_ref().is_none_or(|session| {
        session.display_range.is_none()
            && session.fixed_size.is_none()
            && session.lock_on_disconnect.is_none()
            && session.switch_to_greeter.is_none()
            && session.console.as_ref().is_none_or(|console| {
                console.enabled.is_none() && console.display.is_none() && console.xauthority.is_none()
            })
    });
    let features_empty = overrides.features.as_ref().is_none_or(|features| {
        features.usb.is_none() && features.udp.is_none() && features.avc444v2.is_none() && features.wayland.is_none()
    });
    let tls_empty = overrides
        .tls
        .as_ref()
        .is_none_or(|tls| tls.cert.is_none() && tls.key.is_none());
    session_empty && features_empty && tls_empty && overrides.log.is_none()
}

/// The last segment of a dotted path: what the key is called in the file.
pub(crate) fn leaf_name(schema: &str) -> &str {
    schema.rsplit('.').next().unwrap_or(schema)
}

/// Whether a rendered value is the documented default, for the marker column.
fn is_default(schema: &str, value: &str) -> bool {
    meta::field(schema)
        .and_then(|field| field.default)
        .is_some_and(|default| default == value || (default == "unset" && value == "null"))
}

fn opt(value: Option<String>) -> String {
    value.unwrap_or_else(|| "null".to_owned())
}

fn path(value: Option<&PathBuf>) -> Option<String> {
    value.map(|p| p.display().to_string())
}

fn unset_or(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "null" {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn parse_opt<T: core::str::FromStr<Err = anyhow::Error>>(raw: &str) -> anyhow::Result<Option<T>> {
    match unset_or(raw) {
        Some(value) => Ok(Some(value.parse()?)),
        None => Ok(None),
    }
}

/// A limit is a count, and a count of zero is not "unlimited" — it is a
/// service that accepts nothing. Refusing it here is kinder than a port that
/// binds and then turns everybody away.
fn parse_limit(raw: &str, path: &str) -> anyhow::Result<u32> {
    let value: u32 = raw
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{path} takes a whole number, got `{}`", raw.trim()))?;
    anyhow::ensure!(value >= 1, "{path} must be at least 1; 0 would refuse every connection");
    Ok(value)
}

fn parse_bool(raw: &str) -> anyhow::Result<bool> {
    match raw.trim() {
        "true" | "yes" | "on" => Ok(true),
        "false" | "no" | "off" => Ok(false),
        other => anyhow::bail!("expected true or false, got `{other}`"),
    }
}

fn parse_auth(raw: &str) -> anyhow::Result<Auth> {
    match raw.trim() {
        "both" => Ok(Auth::Both),
        "nla" => Ok(Auth::Nla),
        "system" => Ok(Auth::System),
        "greeter" => Ok(Auth::Greeter),
        other => anyhow::bail!(
            "`{other}` is not an authentication mode — expected {}",
            meta::value_list("listeners[].auth")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(body: &str) -> Config {
        serde_norway::from_str(body).expect("parses")
    }

    fn minimal() -> Config {
        config("listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n")
    }

    fn open_everything(model: &mut Model) {
        model.collapsed.clear();
    }

    /// The tree is the schema, not the file. A key nobody has written is still
    /// in it — that is what makes this a way to find out what linrdp can do,
    /// rather than only a way to change what somebody already set.
    #[test]
    fn the_tree_lists_every_key_including_the_ones_nobody_set() {
        let mut model = Model::new(minimal());
        open_everything(&mut model);
        let rows = model.rows();

        for field in meta::FIELDS {
            let name = leaf_name(field.path).trim_end_matches("[]");
            assert!(
                rows.iter().any(|row| row.label == name || row.schema == field.path),
                "`{}` is missing from the tree",
                field.path
            );
        }
    }

    /// An unset key shows its default and says that is what it is, so nobody
    /// reads `udp: true` as a decision somebody made.
    #[test]
    fn an_unset_key_is_shown_as_its_default() {
        let mut model = Model::new(minimal());
        open_everything(&mut model);
        let row = model
            .rows()
            .into_iter()
            .find(|row| row.schema == "features.udp" && row.slot == Some(Slot::Global(Setting::Udp)))
            .expect("row");
        assert_eq!(row.value.as_deref(), Some("true"));
        assert_eq!(row.source, Source::Default);
    }

    #[test]
    fn a_key_the_file_sets_is_marked_as_set() {
        let mut model = Model::new(config(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\nfeatures:\n  usb: true\n",
        ));
        open_everything(&mut model);
        let row = model
            .rows()
            .into_iter()
            .find(|row| row.slot == Some(Slot::Global(Setting::Usb)))
            .expect("row");
        assert_eq!(row.source, Source::Set);
    }

    /// An override row shows what this listener uses; an inherited one shows
    /// the global value and says it is inherited. Without the distinction the
    /// two are the same line with different consequences.
    #[test]
    fn an_override_row_says_whether_it_is_inherited_or_its_own() {
        let mut model = Model::new(config(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n    overrides:\n      features: { usb: true }\n",
        ));
        open_everything(&mut model);
        let rows = model.rows();

        let own = rows
            .iter()
            .find(|row| row.slot == Some(Slot::Override(0, Setting::Usb)))
            .expect("row");
        assert_eq!(own.source, Source::Overridden);
        assert_eq!(own.value.as_deref(), Some("true"));

        let inherited = rows
            .iter()
            .find(|row| row.slot == Some(Slot::Override(0, Setting::Udp)))
            .expect("row");
        assert_eq!(inherited.source, Source::Inherited);
        assert_eq!(
            inherited.value.as_deref(),
            Some("true"),
            "the global value, shown as inherited"
        );
    }

    /// The two service-wide keys are not offered as overrides at all. Offering
    /// them and refusing on Enter would be a worse way to say the same thing.
    #[test]
    fn the_service_wide_keys_are_not_offered_as_overrides() {
        let mut model = Model::new(minimal());
        open_everything(&mut model);
        for key in [Setting::DisplayRange, Setting::LogLevel, Setting::LogFile] {
            assert!(
                !model.rows().iter().any(|row| row.slot == Some(Slot::Override(0, key))),
                "{} is offered as an override",
                key.schema()
            );
        }
    }

    /// Editing has to refuse in place everything the file would refuse, or
    /// `linrdp config` saves a file the service will not start on — which is
    /// the worst possible moment to find out.
    #[test]
    fn a_duplicate_bind_is_refused_in_place() {
        let mut model = Model::new(config(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n  - bind: 0.0.0.0:3390\n    auth: both\n",
        ));
        let error = Slot::Bind(1)
            .set(&mut model.config, "0.0.0.0:3389")
            .expect_err("refused");
        assert!(format!("{error:#}").contains("already bound"), "got: {error:#}");
        assert_eq!(
            model.config.listeners[1].bind, "0.0.0.0:3390",
            "and the edit did not land"
        );
    }

    #[test]
    fn a_value_that_is_not_an_address_is_refused_in_place() {
        let mut model = Model::new(minimal());
        Slot::Bind(0)
            .set(&mut model.config, "localhost:3389")
            .expect_err("not an address");
    }

    /// Setting an override and clearing it again must leave the file exactly
    /// as it was, not `overrides: {}` where somebody changed their mind.
    #[test]
    fn clearing_the_last_override_removes_the_block_entirely() {
        let mut model = Model::new(minimal());
        let slot = Slot::Override(0, Setting::Usb);

        slot.set(&mut model.config, "true").expect("set");
        assert!(model.config.listeners[0].overrides.is_some());

        slot.clear(&mut model.config).expect("cleared");
        assert!(
            model.config.listeners[0].overrides.is_none(),
            "no empty block left behind"
        );
    }

    /// A service with no listeners does not load, so the editor may not let
    /// somebody create one.
    #[test]
    fn the_last_listener_cannot_be_removed() {
        let mut model = Model::new(minimal());
        let error = model.remove_listener(0).expect_err("refused");
        assert!(format!("{error:#}").contains("only listener"), "got: {error:#}");
    }

    /// A listener added from the editor has to be one the file accepts — in
    /// particular, not a second one on a port already taken.
    #[test]
    fn an_added_listener_lands_on_a_free_port() {
        let mut model = Model::new(minimal());
        model.add_listener().expect("added");
        assert_eq!(model.config.listeners[1].bind, "0.0.0.0:3390");
        model.add_listener().expect("added");
        assert_eq!(model.config.listeners[2].bind, "0.0.0.0:3391");
        crate::config::validate(&model.config).expect("still valid");
    }

    /// Whatever the editor produces has to survive the round trip through the
    /// file, or saving is a way to lose work.
    #[test]
    fn an_edited_configuration_still_renders_and_reloads() {
        let mut model = Model::new(minimal());
        model.add_listener().expect("added");
        Slot::ListenerAuth(1).set(&mut model.config, "greeter").expect("auth");
        Slot::Override(1, Setting::Usb)
            .set(&mut model.config, "true")
            .expect("override");
        Slot::Global(Setting::FixedSize)
            .set(&mut model.config, "2880x1800")
            .expect("size");
        Slot::Global(Setting::LogFile)
            .set(&mut model.config, "null")
            .expect("unset");

        let rendered = crate::config::render(&model.config);
        let reloaded: Config = serde_norway::from_str(&rendered).expect("parses");
        assert_eq!(reloaded, model.config);
        crate::config::validate(&reloaded).expect("valid");
    }

    /// Folding a branch must not leave the cursor pointing past the end of the
    /// tree, which is where a panic on the next redraw comes from.
    #[test]
    fn the_cursor_survives_a_branch_being_folded() {
        let mut model = Model::new(minimal());
        open_everything(&mut model);
        model.cursor = model.rows().len() - 1;

        model.toggle("log");
        model.toggle("tls");
        model.toggle("features");
        model.toggle("session");
        model.toggle("listeners");
        model.clamp();

        assert!(model.selected().is_some(), "the cursor is on a row that exists");
    }
}
