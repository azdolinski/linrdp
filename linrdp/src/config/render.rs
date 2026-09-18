//! Turn a [`Config`] back into the file an operator reads.
//!
//! The comments come from [`meta`], never from the file that was parsed: serde
//! cannot round-trip YAML comments, so `linrdp config` saves by rendering the
//! whole file afresh. That is also what keeps the descriptions honest — they
//! describe the binary doing the writing, not the binary that wrote the file
//! last year.
//!
//! The cost is that an operator's own comments do not survive a save, which is
//! why `linrdp config` writes `config.yaml.bak` first and says so.

use core::fmt::Write as _;

use super::meta::{self, Kind};
use super::{Config, Listener, Overrides};

/// Where comments wrap. Narrow enough to stay readable in a terminal that is
/// showing a diff side by side.
const WIDTH: usize = 78;

const HEADER: &str = "\
linrdp configuration — the whole of it.

The systemd unit carries no parameters and no environment, so this file is the
only place the service is configured, and `linrdp doctor` reads it rather than
guessing from the unit.

Changing the set of listeners takes effect on `systemctl restart linrdp`; every
other key is read again for each new connection.

`linrdp config` edits this file with the same descriptions you see here. It
rewrites the file completely when you save, so comments you add by hand are
replaced — it keeps the previous version as config.yaml.bak.";

/// Render `config` as the commented file it is written to disk as.
pub(crate) fn render(config: &Config) -> String {
    let mut out = String::new();

    // Wrap by paragraph, not by source line: re-wrapping text that already has
    // newlines leaves a trail of one-word lines.
    for (n, paragraph) in HEADER.split("\n\n").enumerate() {
        if n > 0 {
            out.push_str("#\n");
        }
        for wrapped in wrap(paragraph, WIDTH - 2) {
            let _ = writeln!(out, "# {wrapped}");
        }
    }
    out.push('\n');

    block(&mut out, "listeners", 0);
    out.push_str("listeners:\n");
    for (index, listener) in config.listeners.iter().enumerate() {
        // Only the first listener carries the descriptions. Repeating them for
        // every port turns a five-listener file into something nobody scrolls
        // through, and they are identical a screen further up.
        render_listener(&mut out, listener, index == 0);
    }
    out.push('\n');

    block(&mut out, "session", 0);
    out.push_str("session:\n");
    leaf(
        &mut out,
        "session.display_range",
        &config.session.display_range.to_string(),
        2,
    );
    leaf(
        &mut out,
        "session.fixed_size",
        &opt(config.session.fixed_size.map(|s| s.to_string())),
        2,
    );
    leaf(
        &mut out,
        "session.lock_on_disconnect",
        &config.session.lock_on_disconnect.to_string(),
        2,
    );
    leaf(
        &mut out,
        "session.switch_to_greeter",
        &config.session.switch_to_greeter.to_string(),
        2,
    );
    block(&mut out, "session.console", 2);
    out.push_str("  console:\n");
    leaf(
        &mut out,
        "session.console.enabled",
        &config.session.console.enabled.to_string(),
        4,
    );
    leaf(
        &mut out,
        "session.console.display",
        &opt(config.session.console.display.clone()),
        4,
    );
    leaf(
        &mut out,
        "session.console.xauthority",
        &opt(config
            .session
            .console
            .xauthority
            .as_ref()
            .map(|p| p.display().to_string())),
        4,
    );
    out.push('\n');

    block(&mut out, "features", 0);
    out.push_str("features:\n");
    leaf(&mut out, "features.usb", &config.features.usb.to_string(), 2);
    leaf(&mut out, "features.udp", &config.features.udp.to_string(), 2);
    leaf(&mut out, "features.avc444v2", &config.features.avc444v2.to_string(), 2);
    leaf(&mut out, "features.wayland", &config.features.wayland.to_string(), 2);
    out.push('\n');

    block(&mut out, "tls", 0);
    out.push_str("tls:\n");
    leaf(
        &mut out,
        "tls.cert",
        &opt(config.tls.cert.as_ref().map(|p| p.display().to_string())),
        2,
    );
    leaf(
        &mut out,
        "tls.key",
        &opt(config.tls.key.as_ref().map(|p| p.display().to_string())),
        2,
    );
    out.push('\n');

    block(&mut out, "log", 0);
    out.push_str("log:\n");
    leaf(&mut out, "log.level", &config.log.level, 2);
    leaf(
        &mut out,
        "log.file",
        &opt(config.log.file.as_ref().map(|p| p.display().to_string())),
        2,
    );

    out
}

fn render_listener(out: &mut String, listener: &Listener, described: bool) {
    if described {
        out.push('\n');
        comment(out, "listeners[].bind", 4);
    }
    let _ = writeln!(out, "  - bind: {}", scalar(&listener.bind));

    if described {
        out.push('\n');
        comment(out, "listeners[].auth", 4);
    }
    let _ = writeln!(out, "    auth: {}", listener.auth);

    let Some(overrides) = &listener.overrides else {
        return;
    };
    if described {
        out.push('\n');
        comment(out, "listeners[].overrides", 4);
    }
    out.push_str("    overrides:\n");
    render_overrides(out, overrides);
}

/// Overrides carry no comments of their own: every key in here is described
/// where it lives, in the block it overrides.
fn render_overrides(out: &mut String, overrides: &Overrides) {
    if let Some(session) = &overrides.session {
        out.push_str("      session:\n");
        if let Some(fixed_size) = session.fixed_size {
            let _ = writeln!(out, "        fixed_size: {}", opt(fixed_size.map(|s| s.to_string())));
        }
        if let Some(lock) = session.lock_on_disconnect {
            let _ = writeln!(out, "        lock_on_disconnect: {lock}");
        }
        if let Some(switch) = session.switch_to_greeter {
            let _ = writeln!(out, "        switch_to_greeter: {switch}");
        }
        if let Some(console) = &session.console {
            out.push_str("        console:\n");
            if let Some(enabled) = console.enabled {
                let _ = writeln!(out, "          enabled: {enabled}");
            }
            if let Some(display) = &console.display {
                let _ = writeln!(out, "          display: {}", opt(display.clone()));
            }
            if let Some(xauthority) = &console.xauthority {
                let rendered = opt(xauthority.as_ref().map(|p| p.display().to_string()));
                let _ = writeln!(out, "          xauthority: {rendered}");
            }
        }
    }

    if let Some(features) = &overrides.features {
        out.push_str("      features:\n");
        for (key, value) in [
            ("usb", features.usb),
            ("udp", features.udp),
            ("avc444v2", features.avc444v2),
            ("wayland", features.wayland),
        ] {
            if let Some(value) = value {
                let _ = writeln!(out, "        {key}: {value}");
            }
        }
    }

    if let Some(tls) = &overrides.tls {
        out.push_str("      tls:\n");
        if let Some(cert) = &tls.cert {
            let _ = writeln!(
                out,
                "        cert: {}",
                opt(cert.as_ref().map(|p| p.display().to_string()))
            );
        }
        if let Some(key) = &tls.key {
            let _ = writeln!(
                out,
                "        key: {}",
                opt(key.as_ref().map(|p| p.display().to_string()))
            );
        }
    }
}

/// The description of a heading, with a blank line before it.
fn block(out: &mut String, path: &str, indent: usize) {
    comment(out, path, indent);
}

/// `key: value` under its description.
fn leaf(out: &mut String, path: &str, value: &str, indent: usize) {
    comment(out, path, indent);
    let key = path.rsplit('.').next().unwrap_or(path);
    let _ = writeln!(out, "{:indent$}{key}: {value}", "", indent = indent);
}

/// The comment block for one key: description, the values it accepts, and what
/// it is when nobody sets it.
fn comment(out: &mut String, path: &str, indent: usize) {
    let Some(field) = meta::field(path) else {
        return;
    };
    let pad = " ".repeat(indent);
    let text_width = WIDTH.saturating_sub(indent + 2);

    for line in wrap(field.description, text_width) {
        let _ = writeln!(out, "{pad}# {line}");
    }

    if let Kind::Enum(values) = &field.kind {
        let widest = values.iter().map(|v| v.name.len()).max().unwrap_or(0);
        for value in *values {
            let lead = format!("  {:widest$}  ", value.name, widest = widest);
            let hanging = " ".repeat(lead.len());
            for (n, line) in wrap(value.gloss, text_width.saturating_sub(lead.len()))
                .into_iter()
                .enumerate()
            {
                let prefix = if n == 0 { &lead } else { &hanging };
                let _ = writeln!(out, "{pad}#{prefix}{line}");
            }
        }
    }

    if let Some(default) = field.default {
        let _ = writeln!(out, "{pad}# default: {default}");
    }
}

/// `null` where a key is genuinely unset, so the absence is written down
/// rather than left to be noticed.
fn opt(value: Option<String>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| scalar(&v))
}

/// Quote a scalar unless it is plainly safe unquoted.
///
/// `[::1]:3389` opens with a flow-sequence indicator and `:0` with a mapping
/// one; either would be read back as something other than the string that was
/// written.
fn scalar(value: &str) -> String {
    let safe = !value.is_empty()
        && value.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '/' || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:,=+-".contains(c))
        && !value.contains(": ")
        && !value.ends_with(':');
    if safe {
        value.to_owned()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

/// Greedy wrap. No hyphenation, and a word longer than the width gets its own
/// line rather than being broken.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(20);
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.is_empty() {
            current.push_str(word);
        } else if current.len() + 1 + word.len() <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(core::mem::take(&mut current));
            current.push_str(word);
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::validate;

    fn parse(body: &str) -> Config {
        serde_norway::from_str(body).expect("parses")
    }

    const RICH: &str = "\
listeners:
  - bind: 0.0.0.0:3389
    auth: both
  - bind: \"[::1]:3390\"
    auth: greeter
    overrides:
      features: { usb: true }
      session:
        fixed_size: null
        console: { enabled: false }
      tls: { cert: /etc/ssl/a.pem, key: /etc/ssl/a.key }
session:
  display_range: 20-40
  fixed_size: 2880x1800
  console: { enabled: true, display: \":0\" }
features:
  udp: false
log:
  level: info,ironrdp=warn
  file: null
";

    /// The one guarantee the whole render-on-save design rests on: a file
    /// linrdp writes is a file linrdp starts on. Without it `linrdp config`
    /// could save something the service then refuses, which is the worst
    /// possible moment to find out.
    #[test]
    fn a_rendered_file_parses_back_to_what_it_was_rendered_from() {
        for body in [RICH, "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n"] {
            let original = parse(body);
            let rendered = render(&original);
            let reparsed: Config = serde_norway::from_str(&rendered)
                .unwrap_or_else(|e| panic!("rendered file does not parse: {e}\n---\n{rendered}"));
            assert_eq!(original, reparsed, "rendered:\n{rendered}");
        }
    }

    /// And it is a file that passes the rules, not merely one that parses.
    #[test]
    fn a_rendered_file_still_validates() {
        let rendered = render(&parse(RICH));
        let reparsed: Config = serde_norway::from_str(&rendered).expect("parses");
        validate(&reparsed).expect("a file we wrote ourselves must be valid");
    }

    /// The file is the documentation — a key rendered without its description
    /// is a setting the operator can only learn about from the source.
    #[test]
    fn every_key_is_described_where_it_is_written() {
        // The first listener is the described one, so it is the one that has
        // to carry an `overrides` block for this check to see that key at all.
        let rendered = render(&parse(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n    overrides:\n      features: { usb: true }\n",
        ));
        let lines: Vec<&str> = rendered.lines().collect();
        for field in meta::FIELDS {
            let key = field.path.rsplit('.').next().unwrap_or(field.path);
            let key = key.trim_end_matches("[]");
            let described = lines.iter().enumerate().any(|(n, line)| {
                // A listener's first key is written as a list item, `- bind:`.
                line.trim_start()
                    .trim_start_matches("- ")
                    .starts_with(&format!("{key}:"))
                    && n > 0
                    && lines[n - 1].trim_start().starts_with('#')
            });
            assert!(
                described,
                "`{}` is written with no comment above it:\n{rendered}",
                field.path
            );
        }
    }

    /// Every value of an enum has to reach the file, or the operator learns
    /// about `greeter` only by reading the source.
    #[test]
    fn every_auth_value_is_spelled_out_in_the_file() {
        let rendered = render(&parse("listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n"));
        for value in meta::values("listeners[].auth") {
            assert!(rendered.contains(value.name), "`{}` is not in the file", value.name);
        }
    }

    /// A v6 address opens with `[`, which YAML reads as a flow sequence.
    #[test]
    fn an_address_that_needs_quoting_gets_it() {
        assert_eq!(scalar("[::1]:3389"), "\"[::1]:3389\"");
        assert_eq!(scalar(":0"), "\":0\"");
        assert_eq!(scalar("0.0.0.0:3389"), "0.0.0.0:3389");
        assert_eq!(scalar("/var/log/linrdp/linrdp.log"), "/var/log/linrdp/linrdp.log");
    }

    /// Only the first listener carries the prose; five ports should not mean
    /// five copies of the same four paragraphs.
    #[test]
    fn only_the_first_listener_repeats_the_descriptions() {
        let rendered = render(&parse(RICH));
        let occurrences = rendered.matches("How a login is verified").count();
        assert_eq!(occurrences, 1, "the auth description appears once:\n{rendered}");
    }
}
