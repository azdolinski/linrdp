//! The rules serde cannot express.
//!
//! Everything here refuses; nothing here repairs. A configuration that is
//! wrong stops the service with an explanation, because the alternative —
//! quietly choosing something plausible — is how a port ends up accepting
//! logins in a weaker mode than the operator wrote down, with nothing anywhere
//! saying so.
//!
//! Every problem in the file is reported at once. An operator with two typos
//! should learn both in one run rather than in two restarts.

use core::net::SocketAddr;
use core::str::FromStr as _;

use super::meta;
use super::{Auth, Config, Listener};

/// Check the rules that span fields, and report all violations together.
pub(crate) fn validate(config: &Config) -> anyhow::Result<()> {
    let mut problems: Vec<String> = Vec::new();

    if config.listeners.is_empty() {
        problems.push(
            "`listeners` is empty: a service that binds nothing accepts nothing. Give it at \
             least one address, e.g. `- bind: 0.0.0.0:3389` with `auth: both`."
                .to_owned(),
        );
    }

    let mut seen_literal: Vec<&str> = Vec::new();
    let mut seen_socket: Vec<(SocketAddr, &str)> = Vec::new();

    for listener in &config.listeners {
        check_bind(listener, &mut seen_literal, &mut seen_socket, &mut problems);
        check_overrides(listener, &mut problems);
        check_console(listener, config, &mut problems);
    }

    check_tls(config, &mut problems);

    match problems.len() {
        0 => Ok(()),
        1 => anyhow::bail!("{}", problems[0]),
        n => anyhow::bail!("{n} problems in the configuration:\n  - {}", problems.join("\n  - ")),
    }
}

/// `bind` must be an address and port, and must name its listener uniquely.
///
/// Both halves serve the same mechanism: the supervisor hands a worker the
/// literal from this file and the worker looks its listener up by it. A
/// hostname would resolve to something the worker cannot match, and a repeated
/// address would make two listeners indistinguishable — in either case the
/// worker would be serving a port it cannot describe.
fn check_bind<'cfg>(
    listener: &'cfg Listener,
    seen_literal: &mut Vec<&'cfg str>,
    seen_socket: &mut Vec<(SocketAddr, &'cfg str)>,
    problems: &mut Vec<String>,
) {
    let bind = listener.bind.as_str();

    if seen_literal.contains(&bind) {
        problems.push(format!(
            "two listeners are bound to `{bind}`. Each listener is identified by its \
             address, so a repeated one leaves no way to say which settings a connection \
             should get."
        ));
        return;
    }
    seen_literal.push(bind);

    let parsed = match SocketAddr::from_str(bind) {
        Ok(parsed) => parsed,
        Err(_) => {
            let shape = meta::shape("listeners[].bind").unwrap_or("ADDRESS:PORT");
            problems.push(format!(
                "`{bind}` is not an address and port. listeners[].bind expects {shape} — a \
                 hostname is not accepted, because it may resolve to a different address \
                 than the one this file names."
            ));
            return;
        }
    };

    if let Some((_, other)) = seen_socket.iter().find(|(addr, _)| *addr == parsed) {
        problems.push(format!(
            "`{bind}` and `{other}` are two spellings of the same socket. One of them has \
             to go: they cannot be told apart once a connection arrives."
        ));
        return;
    }
    seen_socket.push((parsed, bind));
}

/// Refuse the two keys that cannot be per-listener, with the reason attached.
fn check_overrides(listener: &Listener, problems: &mut Vec<String>) {
    let bind = &listener.bind;
    let Some(overrides) = &listener.overrides else {
        return;
    };

    if overrides.log.is_some() {
        problems.push(format!(
            "listener `{bind}` overrides `log`, which is a service-wide setting: {}",
            meta::LOG_IS_GLOBAL
        ));
    }

    if overrides.session.as_ref().is_some_and(|s| s.display_range.is_some()) {
        problems.push(format!(
            "listener `{bind}` overrides `session.display_range`, which is a service-wide \
             setting: {}",
            meta::RANGE_IS_GLOBAL
        ));
    }
}

/// The shared screen has to be named, and it cannot be combined with a logon
/// form drawn on a screen of its own.
fn check_console(listener: &Listener, config: &Config, problems: &mut Vec<String>) {
    let bind = &listener.bind;
    // Read through the merge so that a console enabled globally and a console
    // enabled on this listener are held to the same rule.
    let Ok(effective) = config.effective(bind) else {
        // The lookup can only fail for a listener that is not in this config,
        // and every caller here is iterating that very list.
        return;
    };

    if !effective.session.console.enabled {
        return;
    }

    if effective.session.console.display.is_none() {
        problems.push(format!(
            "listener `{bind}` has `session.console.enabled: true` but no \
             `session.console.display`. There is deliberately no default: guessing which \
             screen to share would serve somebody else's desktop to whoever connects."
        ));
    }

    if effective.auth == Auth::Greeter {
        problems.push(format!(
            "listener `{bind}` combines `auth: greeter` with `session.console.enabled: \
             true`. The shared screen is attached before any form could be drawn, so the \
             logon screen would never appear — pick one."
        ));
    }
}

/// A certificate without its key is not an identity.
fn check_tls(config: &Config, problems: &mut Vec<String>) {
    complain_about_a_half_identity("tls", &config.tls, problems);

    for listener in &config.listeners {
        if listener.overrides.as_ref().is_none_or(|o| o.tls.is_none()) {
            continue;
        }
        let Ok(effective) = config.effective(&listener.bind) else {
            continue;
        };
        complain_about_a_half_identity(
            &format!("listener `{}`", listener.bind),
            &effective.tls,
            problems,
        );
    }
}

fn complain_about_a_half_identity(where_: &str, tls: &super::Tls, problems: &mut Vec<String>) {
    match (&tls.cert, &tls.key) {
        (Some(_), None) => problems.push(format!(
            "{where_} sets `tls.cert` without `tls.key`. Set both — a certificate without \
             its key cannot serve a connection."
        )),
        (None, Some(_)) => problems.push(format!(
            "{where_} sets `tls.key` without `tls.cert`. Set both, or neither to let linrdp \
             keep a self-signed identity of its own."
        )),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> anyhow::Result<Config> {
        let config: Config = serde_norway::from_str(body)?;
        validate(&config)?;
        Ok(config)
    }

    fn refusal(body: &str) -> String {
        format!("{:#}", parse(body).expect_err("should have been refused"))
    }

    /// The worker finds its settings by matching this string, so two listeners
    /// wearing it would be indistinguishable the moment a connection arrived.
    #[test]
    fn two_listeners_on_the_same_bind_are_refused() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n  - bind: 0.0.0.0:3389\n    auth: nla\n",
        );
        assert!(message.contains("two listeners are bound to `0.0.0.0:3389`"), "got: {message}");
    }

    /// Same socket, two spellings — the duplicate check has to see through the
    /// notation, or the literal match downstream becomes a coin toss.
    #[test]
    fn one_socket_written_two_ways_is_still_a_duplicate() {
        let message = refusal(
            "listeners:\n  - bind: 127.0.0.1:3389\n    auth: both\n  - bind: 127.0.0.1:3389\n    auth: nla\n",
        );
        assert!(message.contains("3389"), "got: {message}");
    }

    /// A hostname may resolve to an address this file does not name, and the
    /// worker's lookup would then have nothing to match.
    #[test]
    fn a_bind_that_is_not_address_and_port_is_refused() {
        for bad in ["localhost:3389", "3389", "0.0.0.0"] {
            let message = refusal(&format!("listeners:\n  - bind: {bad}\n    auth: both\n"));
            assert!(message.contains("ADDRESS:PORT"), "`{bad}` got: {message}");
        }
    }

    /// Two ranges on two ports would hand the same person two desktops, one
    /// per port — the flock in /run/linrdp is what stops that, and it is one
    /// flock.
    #[test]
    fn an_override_of_the_display_range_is_refused_and_says_why() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n    overrides:\n      session: { display_range: 20-30 }\n",
        );
        assert!(message.contains("display numbers are handed out"), "got: {message}");
    }

    /// One process writes one log; the refusal has to say that, because the
    /// key plainly exists one level up.
    #[test]
    fn an_override_of_the_log_block_is_refused_and_says_why() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n    overrides:\n      log: { level: debug }\n",
        );
        assert!(message.contains("one process writes one log"), "got: {message}");
    }

    /// Without a display, console mode falls back to an ambient :99 — which is
    /// either somebody else's screen or nobody's.
    #[test]
    fn console_without_a_display_is_refused() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\nsession:\n  console: { enabled: true }\n",
        );
        assert!(message.contains("console.display"), "got: {message}");
    }

    /// The router attaches the shared screen before it would ever draw a form,
    /// so this pair means the logon screen silently never appears.
    #[test]
    fn console_on_a_greeter_listener_is_refused() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3390\n    auth: greeter\nsession:\n  console: { enabled: true, display: \":0\" }\n",
        );
        assert!(message.contains("never appear"), "got: {message}");
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let message = refusal(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\ntls:\n  cert: /etc/ssl/linrdp.pem\n",
        );
        assert!(message.contains("without `tls.key`"), "got: {message}");
    }

    /// A service that binds nothing is never what anyone meant.
    #[test]
    fn a_config_with_no_listeners_is_refused() {
        let message = refusal("listeners: []\n");
        assert!(message.contains("binds nothing"), "got: {message}");
    }

    /// Two typos should cost one restart, not two.
    #[test]
    fn every_problem_is_reported_not_just_the_first() {
        let message = refusal(
            "listeners:\n  - bind: nonsense\n    auth: both\n  - bind: also-nonsense\n    auth: nla\n",
        );
        assert!(message.contains("2 problems"), "got: {message}");
        assert!(message.contains("nonsense") && message.contains("also-nonsense"), "got: {message}");
    }

    /// The shape every deployment starts from has to survive validation.
    #[test]
    fn the_two_listener_deployment_this_replaces_is_valid() {
        parse(
            "listeners:\n  - bind: 0.0.0.0:3389\n    auth: both\n  - bind: 0.0.0.0:3390\n    auth: greeter\n",
        )
        .expect("the shape of the two units this replaces");
    }
}
