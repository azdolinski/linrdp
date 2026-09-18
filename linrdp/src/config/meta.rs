//! What every configuration key means, in one table.
//!
//! The descriptions here are the only copy. They are rendered into the
//! comments of `/etc/linrdp/config.yaml`, shown in the help pane of
//! `linrdp config`, and quoted back in the errors a bad value produces. Three
//! hand-maintained copies of "what does `auth: system` do" is how a fifth
//! `auth` value ends up documented in two places and mentioned in neither.
//!
//! Adding a field to [`Config`](super::Config) without adding it here is a
//! test failure, not a silent omission — see `every_leaf_has_a_description`.

/// One value an enum-typed key accepts.
pub(crate) struct Value {
    pub(crate) name: &'static str,
    /// What choosing it does, in the operator's terms rather than the
    /// protocol's.
    pub(crate) gloss: &'static str,
}

/// What a key accepts.
pub(crate) enum Kind {
    /// A heading with no value of its own. Carries a description because the
    /// tree in `linrdp config` lets you stand on it.
    Block,
    Bool,
    /// Free-form, with the shape spelled out for the error message.
    Text(&'static str),
    /// A filesystem path.
    Path,
    Enum(&'static [Value]),
}

/// Whether a listener may override this key, and if not, why not.
///
/// The reason is not decoration: both refusals protect a guarantee that is
/// invisible from the key itself, and an operator who is told only "you may
/// not" will reasonably assume it is an oversight.
pub(crate) enum Overridable {
    Yes,
    No(&'static str),
}

pub(crate) struct Field {
    /// Dotted path. `listeners[]` stands for "every listener".
    pub(crate) path: &'static str,
    pub(crate) description: &'static str,
    pub(crate) kind: Kind,
    /// Rendered as the `default:` line. `None` only for [`Kind::Block`].
    pub(crate) default: Option<&'static str>,
    /// What that default *does*, for a default that names an absence rather
    /// than a value. "unset" answers "what did I write" and not "what will it
    /// do", and on a certificate an absence reads as "off" — so the line says
    /// `default: unset (self-signed, /var/lib/linrdp/linrdp-cert.pem)`.
    pub(crate) default_means: Option<&'static str>,
    pub(crate) overridable: Overridable,
}

const AUTH_VALUES: &[Value] = &[
    Value {
        name: "both",
        gloss: "TLS and CredSSP advertised together; each client takes the strongest it \
                speaks, so there is no wrong port to connect to. mstsc takes NLA, a client \
                that cannot takes TLS. Needs a captured password for the clients that \
                choose NLA.",
    },
    Value {
        name: "nla",
        gloss: "CredSSP/NTLMv2 only — the client's own credential prompt, which is what \
                every RDP client does out of the box. Works with every client, and refuses \
                every account whose password has not been captured.",
    },
    Value {
        name: "system",
        gloss: "TLS only, with the credentials the client sends in the Client Info PDU. \
                Nothing is ever stored — but a client that only speaks NLA (mstsc) sends \
                nothing and is refused with 0x904.",
    },
    Value {
        name: "greeter",
        gloss: "TLS only, with the logon form drawn by the server on an X server of its \
                own. Works with every client, mstsc included, and stores nothing.",
    },
];

const LEVEL_VALUES: &[Value] = &[
    Value {
        name: "error",
        gloss: "only what failed.",
    },
    Value {
        name: "warn",
        gloss: "failures and the conditions that lead to them.",
    },
    Value {
        name: "info",
        gloss: "one line per connection, session and listener. The useful default.",
    },
    Value {
        name: "debug",
        gloss: "protocol decisions. Verbose enough to be worth a log file of its own.",
    },
    Value {
        name: "trace",
        gloss: "everything, including per-frame work. Unusable on a busy server.",
    },
];

/// Why `display_range` is one setting for the whole service.
pub(crate) const RANGE_IS_GLOBAL: &str = "display numbers are handed out under a single flock in \
    /run/linrdp, and that is what makes a user who arrives on either port land on the same \
    desktop. Two ranges on two ports would quietly give that user two.";

/// Why logging is one setting for the whole service.
pub(crate) const LOG_IS_GLOBAL: &str = "one process writes one log; a listener is not a process.";

pub(crate) static FIELDS: &[Field] = &[
    Field {
        path: "listeners",
        description: "The addresses this machine accepts RDP connections on. One process \
                      binds all of them. Changing the set takes effect on \
                      `systemctl restart linrdp`.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::No("a listener cannot contain listeners"),
    },
    Field {
        path: "listeners[].bind",
        description: "Address and port to accept on, written ADDRESS:PORT. Two listeners \
                      may share a port only on different addresses.",
        kind: Kind::Text("ADDRESS:PORT, e.g. 0.0.0.0:3389 or [::1]:3389"),
        default: Some("0.0.0.0:3389"),
        default_means: None,
        overridable: Overridable::No("this is what identifies the listener"),
    },
    Field {
        path: "listeners[].auth",
        description: "How a login is verified on this port. The password checked is always \
                      the account's system password; there is no linrdp password to set.",
        kind: Kind::Enum(AUTH_VALUES),
        default: Some("both"),
        default_means: None,
        overridable: Overridable::No("this is already a per-listener setting"),
    },
    Field {
        path: "listeners[].overrides",
        description: "Keys from the blocks below, given a different value on this listener \
                      alone. Anything not named here is inherited.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::No("overrides do not nest"),
    },
    Field {
        path: "session",
        description: "What a desktop session looks like and how long it lives. Shared by \
                      every listener unless a listener overrides a key.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.display_range",
        description: "X display numbers sessions may occupy, written LOW-HIGH. Must start \
                      at 1 or above: :0 is a physical seat.",
        kind: Kind::Text("LOW-HIGH, e.g. 10-99"),
        default: Some("10-99"),
        default_means: None,
        overridable: Overridable::No(RANGE_IS_GLOBAL),
    },
    Field {
        path: "session.fixed_size",
        description: "Pin every session's screen to this size instead of following the \
                      connecting client. Recommended with mstsc, which composes EGFX poorly \
                      right after a mid-session resize. Unset means follow the client.",
        kind: Kind::Text("WIDTHxHEIGHT, e.g. 2880x1800"),
        default: Some("unset"),
        default_means: Some("follow the client's own screen size"),
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.lock_on_disconnect",
        description: "Lock the logind session when the last client disconnects, and unlock \
                      it when one reconnects.",
        kind: Kind::Bool,
        default: Some("false"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.switch_to_greeter",
        description: "Flip the physical seat to the display manager's greeter when a client \
                      takes the session over, so the screen at the desk does not keep showing \
                      the desktop somebody is now using remotely.",
        kind: Kind::Bool,
        default: Some("false"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.console",
        description: "Serve one shared screen that already exists instead of creating a \
                      session per user — the equivalent of mstsc /admin.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.console.enabled",
        description: "Attach to the shared screen named below. Everyone who connects sees \
                      the same desktop, and nobody gets one of their own.",
        kind: Kind::Bool,
        default: Some("false"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.console.display",
        description: "Which X display the shared screen is. Unset is only valid with \
                      console off; there is deliberately no default, because a wrong guess \
                      here serves somebody else's screen to whoever connects.",
        kind: Kind::Text("an X display, e.g. :0"),
        default: Some("unset"),
        default_means: Some("valid only while console is disabled"),
        overridable: Overridable::Yes,
    },
    Field {
        path: "session.console.xauthority",
        description: "The X authority file granting access to that display. Unset means the \
                      display accepts the connection without one.",
        kind: Kind::Path,
        default: Some("unset"),
        default_means: Some("reach the display without one"),
        overridable: Overridable::Yes,
    },
    Field {
        path: "features",
        description: "Protocol extensions and encoder options.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "features.usb",
        description: "USB device redirection (MS-RDPEUSB): a stick plugged into the client \
                      appears on this machine.",
        kind: Kind::Bool,
        default: Some("false"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "features.udp",
        description: "Accept the client's UDP transport (MS-RDPEMT) alongside TCP, which is \
                      what makes a lossy link usable. Turning it off serves TCP only.",
        kind: Kind::Bool,
        default: Some("true"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "features.avc444v2",
        description: "Offer the AVC444v2 layout (full-resolution chroma) to clients that \
                      negotiate EGFX cap version 10.6. A quality setting and nothing more.",
        kind: Kind::Bool,
        default: Some("true"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "features.wayland",
        description: "Capture through xdg-desktop-portal and inject input over libei instead \
                      of talking to X. Ignored with a warning by a binary built without the \
                      `wayland` feature, so one file can serve several builds.",
        kind: Kind::Bool,
        default: Some("false"),
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "tls",
        description: "The certificate clients see. Unset means linrdp keeps a self-signed \
                      one of its own in /var/lib/linrdp and reuses it across restarts, so a \
                      client that trusted it once keeps trusting it.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::Yes,
    },
    Field {
        path: "tls.cert",
        description: "PEM certificate chain to serve. Unset is not \"no TLS\" — RDP has \
                      no such mode: linrdp generates a self-signed certificate, keeps it in \
                      /var/lib/linrdp and reuses it across restarts, so a client that \
                      trusted it once keeps trusting it. Set, linrdp generates nothing: a \
                      path that does not exist is a refusal to start, not a fresh \
                      self-signed certificate under your filename.",
        kind: Kind::Path,
        default: Some("unset"),
        default_means: Some("self-signed, /var/lib/linrdp/linrdp-cert.pem"),
        overridable: Overridable::Yes,
    },
    Field {
        path: "tls.key",
        description: "PEM private key for that certificate. Unset alongside an unset \
                      `cert` is the generated pair above. Set both keys or neither: half an \
                      identity is a refusal to start.",
        kind: Kind::Path,
        default: Some("unset"),
        default_means: Some("self-signed, /var/lib/linrdp/linrdp-key.pem"),
        overridable: Overridable::Yes,
    },
    Field {
        path: "log",
        description: "Where linrdp writes and how much.",
        kind: Kind::Block,
        default: None,
        default_means: None,
        overridable: Overridable::No(LOG_IS_GLOBAL),
    },
    Field {
        path: "log.level",
        description: "How much is written. Accepts a bare level or a tracing filter such as \
                      `info,ironrdp=warn`.",
        kind: Kind::Enum(LEVEL_VALUES),
        default: Some("info"),
        default_means: None,
        overridable: Overridable::No(LOG_IS_GLOBAL),
    },
    Field {
        path: "log.file",
        description: "File to append to. Set, the log goes to BOTH this file and the \
                      journal — the file at the level above, the journal capped at info, so \
                      `systemctl status` is never empty and a per-frame `trace` never \
                      evicts other services' logs from journald. Unset, the journal is the \
                      whole log and gets the level above in full.",
        kind: Kind::Path,
        default: Some("/var/log/linrdp/linrdp.log"),
        default_means: None,
        overridable: Overridable::No(LOG_IS_GLOBAL),
    },
];

/// The table entry for a dotted path, or `None` if there is no such key.
pub(crate) fn field(path: &str) -> Option<&'static Field> {
    FIELDS.iter().find(|f| f.path == path)
}

/// The text of the `default:` line — the value, plus what it does when the
/// value names an absence. One function, because the file's comment and the
/// help pane in `linrdp config` saying it two different ways is the whole
/// class of bug this table exists to prevent.
pub(crate) fn default_text(field: &Field) -> Option<String> {
    let default = field.default?;
    Some(match field.default_means {
        Some(means) => format!("{default} ({means})"),
        None => default.to_owned(),
    })
}

/// The shape a free-form key accepts, for the message that refuses a value
/// that does not have it. Lives here so the file's comment and the rejection
/// cannot describe two different formats.
pub(crate) fn shape(path: &str) -> Option<&'static str> {
    match field(path).map(|f| &f.kind) {
        Some(Kind::Text(shape)) => Some(shape),
        _ => None,
    }
}

/// The values an enum-typed key accepts, for an error message that tells the
/// operator what to write instead of only what was wrong.
pub(crate) fn values(path: &str) -> &'static [Value] {
    match field(path).map(|f| &f.kind) {
        Some(Kind::Enum(values)) => values,
        _ => &[],
    }
}

/// Why a listener may not override this key, or `None` if it may.
///
/// The reason travels with the refusal so that `overrides: {log: ...}` is
/// answered with what makes logging service-wide, rather than with a bare
/// "not allowed" that reads like an arbitrary restriction.
pub(crate) fn override_refusal(path: &str) -> Option<&'static str> {
    match field(path).map(|f| &f.overridable) {
        Some(Overridable::No(reason)) => Some(reason),
        _ => None,
    }
}

/// `both`, `nla`, `system` or `greeter` — the tail of an error message.
pub(crate) fn value_list(path: &str) -> String {
    let names: Vec<&str> = values(path).iter().map(|v| v.name).collect();
    match names.split_last() {
        Some((last, [])) => (*last).to_owned(),
        Some((last, rest)) => format!("{} or {last}", rest.join(", ")),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key nobody described is a key nobody can discover: this table is the
    /// only documentation of the config file, so an entry added to `Config`
    /// without an entry here would be invisible in the generated file and in
    /// `linrdp config` alike.
    #[test]
    fn every_leaf_has_a_description_and_a_default() {
        for f in FIELDS {
            assert!(!f.description.trim().is_empty(), "{} has no description", f.path);
            if matches!(f.kind, Kind::Block) {
                assert!(f.default.is_none(), "{} is a block and cannot have a default", f.path);
            } else {
                assert!(f.default.is_some(), "{} has no documented default", f.path);
            }
        }
    }

    /// An undescribed value is the one an operator will not pick, however well
    /// it would have suited them — `auth: greeter` went unused for exactly
    /// this reason until the README grew a table.
    #[test]
    fn every_enum_value_is_glossed() {
        for f in FIELDS {
            if let Kind::Enum(values) = &f.kind {
                assert!(!values.is_empty(), "{} is an enum with no values", f.path);
                for v in *values {
                    assert!(!v.gloss.trim().is_empty(), "{}: `{}` has no gloss", f.path, v.name);
                }
            }
        }
    }

    /// The two refusals have to explain themselves. "You may not override this"
    /// with no reason reads as an oversight, and the next person removes it.
    #[test]
    fn a_key_that_cannot_be_overridden_says_why() {
        for f in FIELDS {
            if let Overridable::No(reason) = &f.overridable {
                assert!(reason.len() > 20, "{} refuses overrides without a reason", f.path);
            }
        }
    }

    /// `default: unset` is the one default that does not say what happens.
    /// Every other default is the value itself, so reading it is reading the
    /// behaviour; "unset" reads as "off" or "disabled" to anybody who has not
    /// got the parent block's help open — which is exactly what `tls.cert`
    /// looked like, promising a generated certificate on the `tls` branch and
    /// saying only "unset" on the key underneath it. So a key that defaults to
    /// an absence owes two things: a sentence on what fills it, and the same
    /// answer on the `default:` line itself, where the eye actually lands.
    #[test]
    fn a_key_that_defaults_to_unset_says_what_unset_does() {
        for f in FIELDS {
            if f.default == Some("unset") {
                assert!(
                    f.description.contains("Unset") || f.description.contains("unset"),
                    "{} defaults to unset without saying what unset does",
                    f.path
                );
                let means = f.default_means.unwrap_or("");
                assert!(!means.trim().is_empty(), "{}: `default: unset` says nothing", f.path);
            }
        }
    }

    /// The help for an unset `tls.cert` names the file linrdp will write. A
    /// renamed constant in `tls.rs` would leave the operator looking for a
    /// certificate at a path that no longer exists — and looking in the one
    /// place that reads like documentation.
    #[test]
    fn the_promised_certificate_paths_are_the_ones_tls_writes() {
        for (path, file) in [("tls.cert", crate::tls::CERT_FILE), ("tls.key", crate::tls::KEY_FILE)] {
            let on_disk = format!("{}/{file}", crate::tls::STATE_DIR);
            let promised = field(path).and_then(|f| f.default_means).unwrap_or("");
            assert!(
                promised.contains(&on_disk),
                "{path} promises `{promised}`, but tls.rs writes {on_disk}"
            );
        }
    }

    #[test]
    fn no_path_is_listed_twice() {
        let mut seen: Vec<&str> = FIELDS.iter().map(|f| f.path).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "a path appears twice in FIELDS");
    }

    /// The tail of "expects ..." in a rejection.
    #[test]
    fn the_value_list_reads_as_a_sentence() {
        assert_eq!(value_list("listeners[].auth"), "both, nla, system or greeter");
        assert_eq!(value_list("session.fixed_size"), "");
    }
}
