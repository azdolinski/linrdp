//! `/etc/linrdp/config.yaml` — the only place linrdp is configured.
//!
//! The systemd unit carries no parameters and no environment: everything the
//! service does is decided here, so there is one file to read when answering
//! "why is this machine behaving like that?" and one file to change.
//!
//! Two loaders, deliberately not one loader with a flag. [`load_or_default`]
//! is the only path on which built-in defaults exist at all, and the only
//! caller is the supervisor deciding what to bind on a machine where nobody
//! has written a config yet. Everything else — the worker serving a
//! connection, `doctor`, `service`, `config` — uses [`load_strict`], which has
//! no defaults branch in its body. A worker that fell back to `auth: both`
//! where the operator wrote `system` would authenticate more weakly than
//! anyone asked, in silence; making that a one-character change to a boolean
//! is not a risk worth the shared code.

pub(crate) mod meta;
mod render;
mod validate;

use core::fmt;
use core::ops::RangeInclusive;
use core::str::FromStr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Deserializer, Serialize};

pub(crate) use render::render;
pub(crate) use validate::validate;

/// Where the file lives unless `--config` says otherwise.
pub(crate) const CONFIG_PATH: &str = "/etc/linrdp/config.yaml";

static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Remember which file this process was pointed at.
///
/// Set once, from `--config`, before anything reads the configuration. A
/// process-wide cell rather than a parameter because the keeper is spawned
/// four layers below the entry point that parsed the flag, and threading a
/// path through those four layers to reach one `Command` is how the keeper
/// came to be spawned without `--log-file` in the first place.
pub(crate) fn set_path(path: PathBuf) {
    let _ = PATH.set(path);
}

/// The configuration file this process reads.
pub(crate) fn path() -> &'static Path {
    PATH.get_or_init(|| PathBuf::from(CONFIG_PATH))
}

/// Whether the path is the installed one, i.e. whether a child process needs
/// to be told about it explicitly.
pub(crate) fn path_is_default() -> bool {
    path() == Path::new(CONFIG_PATH)
}

/// The address a listener binds when the file does not exist yet.
const DEFAULT_BIND: &str = "0.0.0.0:3389";

// ---------------------------------------------------------------- scalars

/// `LOW-HIGH`, the X display numbers sessions may occupy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DisplayRange(RangeInclusive<u16>);

impl DisplayRange {
    pub(crate) fn range(&self) -> RangeInclusive<u16> {
        self.0.clone()
    }
}

impl FromStr for DisplayRange {
    type Err = anyhow::Error;

    fn from_str(spec: &str) -> anyhow::Result<Self> {
        let Some((low, high)) = spec.split_once('-') else {
            anyhow::bail!("session.display_range expects LOW-HIGH, e.g. 10-99");
        };
        let low: u16 = low.trim().parse().context("session.display_range LOW")?;
        let high: u16 = high.trim().parse().context("session.display_range HIGH")?;
        anyhow::ensure!(
            low >= 1,
            "session.display_range must start at 1 or above (:0 is a physical seat)"
        );
        anyhow::ensure!(
            low <= high,
            "session.display_range expects LOW-HIGH with LOW <= HIGH"
        );
        Ok(Self(low..=high))
    }
}

impl fmt::Display for DisplayRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.0.start(), self.0.end())
    }
}

/// `WIDTHxHEIGHT`, a pinned screen size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Size {
    pub(crate) width: u16,
    pub(crate) height: u16,
}

impl FromStr for Size {
    type Err = anyhow::Error;

    fn from_str(spec: &str) -> anyhow::Result<Self> {
        let Some((w, h)) = spec.split_once(['x', 'X']) else {
            anyhow::bail!("expects WIDTHxHEIGHT, e.g. 2880x1800");
        };
        let width: u16 = w.trim().parse().context("width")?;
        let height: u16 = h.trim().parse().context("height")?;
        anyhow::ensure!(width >= 1 && height >= 1, "a screen cannot have a zero side");
        Ok(Self { width, height })
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{}", self.width, self.height)
    }
}

/// Both scalars are written as strings in YAML, so both are parsed from one.
macro_rules! string_serde {
    ($ty:ty) => {
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(de)?;
                raw.parse().map_err(|e: anyhow::Error| serde::de::Error::custom(format!("{e:#}")))
            }
        }

        impl Serialize for $ty {
            fn serialize<S: serde::Serializer>(&self, se: S) -> Result<S::Ok, S::Error> {
                se.serialize_str(&self.to_string())
            }
        }
    };
}

string_serde!(DisplayRange);
string_serde!(Size);

/// How a login is verified on a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Auth {
    Both,
    Nla,
    System,
    Greeter,
}

impl Auth {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Nla => "nla",
            Self::System => "system",
            Self::Greeter => "greeter",
        }
    }

    /// Whether this port draws the logon form itself.
    pub(crate) fn is_greeter(self) -> bool {
        matches!(self, Self::Greeter)
    }
}

impl fmt::Display for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------- the file

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) listeners: Vec<Listener>,
    #[serde(default)]
    pub(crate) session: Session,
    #[serde(default)]
    pub(crate) features: Features,
    #[serde(default)]
    pub(crate) tls: Tls,
    #[serde(default)]
    pub(crate) log: Log,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Listener {
    pub(crate) bind: String,
    pub(crate) auth: Auth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) overrides: Option<Overrides>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Session {
    pub(crate) display_range: DisplayRange,
    pub(crate) fixed_size: Option<Size>,
    pub(crate) lock_on_disconnect: bool,
    pub(crate) switch_to_greeter: bool,
    pub(crate) console: Console,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Console {
    pub(crate) enabled: bool,
    pub(crate) display: Option<String>,
    pub(crate) xauthority: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Features {
    pub(crate) usb: bool,
    pub(crate) udp: bool,
    pub(crate) avc444v2: bool,
    pub(crate) wayland: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Tls {
    pub(crate) cert: Option<PathBuf>,
    pub(crate) key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Log {
    pub(crate) level: String,
    pub(crate) file: Option<PathBuf>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            display_range: DisplayRange(10..=99),
            fixed_size: None,
            lock_on_disconnect: false,
            switch_to_greeter: false,
            console: Console::default(),
        }
    }
}

impl Default for Console {
    fn default() -> Self {
        Self { enabled: false, display: None, xauthority: None }
    }
}

impl Default for Features {
    fn default() -> Self {
        Self { usb: false, udp: true, avc444v2: true, wayland: false }
    }
}

impl Default for Tls {
    fn default() -> Self {
        Self { cert: None, key: None }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self { level: "info".to_owned(), file: Some(PathBuf::from("/var/log/linrdp/linrdp.log")) }
    }
}

// ----------------------------------------------------------- the overrides

/// Keys a single listener gives a different value.
///
/// `log` is here only so that writing it produces the refusal that explains
/// why it cannot be per-listener. Left out of the struct it would come back as
/// serde's "unknown field `log`", which tells an operator that the key does not
/// exist — and it does exist, one level up.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct Overrides {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) session: Option<SessionOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) features: Option<FeaturesOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tls: Option<TlsOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) log: Option<serde_norway::Value>,
}

/// `Some(None)` is "written as null here", `None` is "not written at all".
///
/// The difference is the whole point of an override: with a plain `Option`,
/// `fixed_size: null` on a listener would silently mean "inherit the global
/// pin" when what it says is "do not pin this port".
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct SessionOverride {
    /// Accepted by the parser only so that [`validate`] can refuse it with the
    /// reason; see `meta::RANGE_IS_GLOBAL`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) display_range: Option<DisplayRange>,
    #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
    pub(crate) fixed_size: Option<Option<Size>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lock_on_disconnect: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) switch_to_greeter: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) console: Option<ConsoleOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct ConsoleOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) enabled: Option<bool>,
    #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
    pub(crate) display: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
    pub(crate) xauthority: Option<Option<PathBuf>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct FeaturesOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) usb: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) avc444v2: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) wayland: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct TlsOverride {
    #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
    pub(crate) cert: Option<Option<PathBuf>>,
    #[serde(default, deserialize_with = "double_option", skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<Option<PathBuf>>,
}

// ------------------------------------------------------- what a worker uses

/// One listener's settings with its overrides already folded in.
///
/// Nothing downstream should ever see a [`Config`]: a worker serves exactly one
/// listener, and handing it the whole file invites the next person to read a
/// second listener's settings by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Effective {
    pub(crate) bind: String,
    pub(crate) auth: Auth,
    pub(crate) session: Session,
    pub(crate) features: Features,
    pub(crate) tls: Tls,
    pub(crate) log: Log,
}

impl Config {
    /// The configuration of a machine where nobody has written a file yet.
    ///
    /// Private on purpose: [`load_or_default`] is the only way to reach it, so
    /// "did this process fall back to defaults?" has exactly one answer site.
    fn builtin_default() -> Self {
        Self {
            listeners: vec![Listener {
                bind: DEFAULT_BIND.to_owned(),
                auth: Auth::Both,
                overrides: None,
            }],
            session: Session::default(),
            features: Features::default(),
            tls: Tls::default(),
            log: Log::default(),
        }
    }

    /// The listener bound to `bind`, with its overrides applied.
    ///
    /// The match is on the literal from the file, not on a parsed and
    /// re-formatted address: `0.0.0.0:3389`, `[::]:3389` and
    /// `[::ffff:0.0.0.0]:3389` can name one socket, and `SocketAddr::Display`
    /// hands back a spelling the operator never wrote. The supervisor carries
    /// the literal through, so the lookup is total by construction.
    pub(crate) fn effective(&self, bind: &str) -> anyhow::Result<Effective> {
        let listener = self.listeners.iter().find(|l| l.bind == bind).with_context(|| {
            format!(
                "no listener `{bind}` in the configuration (it has: {})",
                self.listeners
                    .iter()
                    .map(|l| l.bind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;

        let mut effective = Effective {
            bind: listener.bind.clone(),
            auth: listener.auth,
            session: self.session.clone(),
            features: self.features,
            tls: self.tls.clone(),
            // Never overridable: one process writes one log.
            log: self.log.clone(),
        };

        let Some(overrides) = &listener.overrides else {
            return Ok(effective);
        };

        if let Some(session) = &overrides.session {
            // display_range is refused by `validate`, so it cannot arrive here.
            if let Some(fixed_size) = session.fixed_size {
                effective.session.fixed_size = fixed_size;
            }
            if let Some(lock) = session.lock_on_disconnect {
                effective.session.lock_on_disconnect = lock;
            }
            if let Some(switch) = session.switch_to_greeter {
                effective.session.switch_to_greeter = switch;
            }
            if let Some(console) = &session.console {
                if let Some(enabled) = console.enabled {
                    effective.session.console.enabled = enabled;
                }
                if let Some(display) = &console.display {
                    effective.session.console.display = display.clone();
                }
                if let Some(xauthority) = &console.xauthority {
                    effective.session.console.xauthority = xauthority.clone();
                }
            }
        }

        if let Some(features) = &overrides.features {
            if let Some(usb) = features.usb {
                effective.features.usb = usb;
            }
            if let Some(udp) = features.udp {
                effective.features.udp = udp;
            }
            if let Some(avc444v2) = features.avc444v2 {
                effective.features.avc444v2 = avc444v2;
            }
            if let Some(wayland) = features.wayland {
                effective.features.wayland = wayland;
            }
        }

        if let Some(tls) = &overrides.tls {
            if let Some(cert) = &tls.cert {
                effective.tls.cert = cert.clone();
            }
            if let Some(key) = &tls.key {
                effective.tls.key = key.clone();
            }
        }

        Ok(effective)
    }
}

// -------------------------------------------------------------- the loaders

/// Parse and validate `body`, naming `path` in any failure.
fn parse(path: &Path, body: &str) -> anyhow::Result<Config> {
    let config: Config = serde_norway::from_str(body)
        .with_context(|| format!("{} is not a valid linrdp configuration", path.display()))?;
    validate(&config).with_context(|| format!("{}", path.display()))?;
    Ok(config)
}

/// A configuration and where it came from.
///
/// `from_defaults` is carried out rather than logged in place because the
/// first thing every caller does with the result is set up logging from it —
/// a line emitted here would be written before there is a subscriber to write
/// it to.
#[derive(Debug)]
pub(crate) struct Loaded {
    pub(crate) config: Config,
    pub(crate) from_defaults: bool,
}

/// Read the configuration, or the built-in defaults when the file does not
/// exist.
///
/// Only the supervisor and the single-process development path call this. A
/// file that exists and is wrong is still an error: the defaults answer
/// "nobody has configured this machine", never "this machine is configured
/// incorrectly".
pub(crate) fn load_or_default(path: &Path) -> anyhow::Result<Loaded> {
    match std::fs::read_to_string(path) {
        Ok(body) => parse(path, &body).map(|config| Loaded { config, from_defaults: false }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(Loaded { config: Config::builtin_default(), from_defaults: true })
        }
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// The configuration as far as it can be read, for a report rather than for a
/// decision.
///
/// `doctor` exists to be run on a machine that is broken, so it must not be
/// the one command that refuses to run when something is wrong with the file.
/// The complaint comes back alongside the defaults so the report can show it
/// as a finding. Nothing that decides how a connection is served may use this.
pub(crate) fn load_for_diagnostics(path: &Path) -> (Config, Option<String>) {
    match load_or_default(path) {
        Ok(loaded) => (loaded.config, None),
        Err(error) => (Config::builtin_default(), Some(format!("{error:#}"))),
    }
}

/// Read the configuration. A missing file is an error like any other.
///
/// There is no defaults branch in this function and there must not be one.
/// Its callers — the worker, `doctor`, `service`, `config` — are all answering
/// "what did the operator ask for?", and a plausible guess is the wrong answer
/// to that question every time.
pub(crate) fn load_strict(path: &Path) -> anyhow::Result<Config> {
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    parse(path, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("linrdp-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("config.yaml");
        std::fs::write(&path, body).expect("write config");
        path
    }

    fn cleanup(path: &Path) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    const MINIMAL: &str = "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n";

    /// A machine nobody has configured still serves, and serves the one thing
    /// every deployment starts from.
    #[test]
    fn a_missing_file_yields_exactly_one_default_listener() {
        let missing = std::env::temp_dir().join(format!("linrdp-absent-{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        let loaded = load_or_default(&missing).expect("defaults");
        assert!(loaded.from_defaults, "the caller has to be able to say so in the log");
        let config = loaded.config;
        assert_eq!(config.listeners.len(), 1);
        assert_eq!(config.listeners[0].bind, DEFAULT_BIND);
        assert_eq!(config.listeners[0].auth, Auth::Both);
    }

    /// "Nobody configured this" and "this configuration is wrong" are different
    /// answers, and only the first one has a safe default.
    #[test]
    fn a_malformed_file_is_an_error_not_the_defaults() {
        let path = temp_file("malformed", "listeners:\n  - bind: 0.0.0.0:3389\n    auth: greter\n");
        let error = load_or_default(&path).expect_err("refused");
        assert!(format!("{error:#}").contains("greter"), "got: {error:#}");
        cleanup(&path);
    }

    /// The rule the whole two-loader split exists for: a worker that cannot
    /// read its configuration must drop the connection, never serve one it
    /// invented. `auth: both` guessed where the operator wrote `system` would
    /// authenticate more weakly than anyone asked, in silence.
    #[test]
    fn the_strict_loader_never_substitutes_defaults() {
        let missing = std::env::temp_dir().join(format!("linrdp-absent2-{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&missing);
        load_strict(&missing).expect_err("a missing file is an error here");

        let garbage = temp_file("garbage", "listeners: [ this is not a listener ]\n");
        load_strict(&garbage).expect_err("garbage is an error here");
        cleanup(&garbage);
    }

    /// Deleting a listener from the file while the service runs must not make
    /// connections to that port fall back to some other listener's settings.
    #[test]
    fn a_listener_the_config_no_longer_has_is_an_error() {
        let config: Config = serde_norway::from_str(MINIMAL).expect("parses");
        let error = config.effective("0.0.0.0:3390").expect_err("no such listener");
        assert!(format!("{error:#}").contains("0.0.0.0:3390"), "got: {error:#}");
    }

    /// An override replaces the keys it names and nothing else — the bug being
    /// guarded is a merge written as "replace the block", which would reset
    /// `udp` to its default on any listener that changed `usb`.
    #[test]
    fn an_override_replaces_only_the_keys_it_names() {
        let body = "\
listeners:
  - bind: 0.0.0.0:3389
    auth: both
  - bind: 0.0.0.0:3390
    auth: greeter
    overrides:
      features: { usb: true }
features:
  usb: false
  udp: false
  avc444v2: true
  wayland: false
";
        let config: Config = serde_norway::from_str(body).expect("parses");
        let overridden = config.effective("0.0.0.0:3390").expect("listener");
        assert!(overridden.features.usb, "the named key is overridden");
        assert!(!overridden.features.udp, "an unnamed key keeps the global value");
        assert!(overridden.features.avc444v2, "and so does this one");

        let plain = config.effective("0.0.0.0:3389").expect("listener");
        assert!(!plain.features.usb, "the other listener is untouched");
    }

    /// Without an `overrides` block a listener is the global configuration.
    #[test]
    fn an_absent_override_block_inherits_every_global() {
        let body = "\
listeners:
  - bind: 0.0.0.0:3389
    auth: nla
session:
  display_range: 20-30
  fixed_size: 1920x1080
  lock_on_disconnect: true
";
        let config: Config = serde_norway::from_str(body).expect("parses");
        let effective = config.effective("0.0.0.0:3389").expect("listener");
        assert_eq!(effective.session.display_range.to_string(), "20-30");
        assert_eq!(effective.session.fixed_size.map(|s| s.to_string()).as_deref(), Some("1920x1080"));
        assert!(effective.session.lock_on_disconnect);
        assert_eq!(effective.auth, Auth::Nla);
    }

    /// `fixed_size: null` on a listener says "do not pin this port", and a
    /// merge built on a plain Option would read it as "inherit the pin" —
    /// the file and the behaviour would disagree with nothing to show for it.
    #[test]
    fn an_override_can_unset_a_value_the_global_block_set() {
        let body = "\
listeners:
  - bind: 0.0.0.0:3390
    auth: both
    overrides:
      session: { fixed_size: null }
session:
  fixed_size: 2880x1800
";
        let config: Config = serde_norway::from_str(body).expect("parses");
        let effective = config.effective("0.0.0.0:3390").expect("listener");
        assert_eq!(effective.session.fixed_size, None, "null means unset, not inherit");
    }

    /// Whichever listener you arrive on, the log is the service's.
    #[test]
    fn the_log_block_is_never_taken_from_a_listener() {
        let body = "\
listeners:
  - bind: 0.0.0.0:3389
    auth: both
log:
  level: debug
  file: /tmp/linrdp-test.log
";
        let config: Config = serde_norway::from_str(body).expect("parses");
        let effective = config.effective("0.0.0.0:3389").expect("listener");
        assert_eq!(effective.log.level, "debug");
    }

    #[test]
    fn a_display_range_round_trips_through_its_written_form() {
        let range: DisplayRange = "10-99".parse().expect("valid");
        assert_eq!(range.to_string(), "10-99");
        assert_eq!(range.range(), 10..=99);
    }

    /// :0 is a physical seat: handing it out would put a remote session on the
    /// screen at somebody's desk.
    #[test]
    fn a_display_range_starting_at_zero_is_refused() {
        let error = "0-9".parse::<DisplayRange>().expect_err("rejected");
        assert!(error.to_string().contains("must start at 1"), "got: {error}");
    }

    #[test]
    fn an_inverted_or_shapeless_display_range_is_refused() {
        "99-10".parse::<DisplayRange>().expect_err("inverted");
        "10".parse::<DisplayRange>().expect_err("no dash");
        "ten to ninety".parse::<DisplayRange>().expect_err("not a range");
    }

    #[test]
    fn a_size_round_trips_through_its_written_form() {
        let size: Size = "2880x1800".parse().expect("valid");
        assert_eq!((size.width, size.height), (2880, 1800));
        assert_eq!(size.to_string(), "2880x1800");
        assert_eq!("1920X1080".parse::<Size>().expect("capital X").width, 1920);
        "1920".parse::<Size>().expect_err("no separator");
        "0x1080".parse::<Size>().expect_err("zero side");
    }
}
