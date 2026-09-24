//! The Secret Service, carried into a headless GNOME session.
//!
//! A headless session has a bus of its own (two GNOME Shells cannot share
//! one), and the account's `gnome-keyring-daemon` is not on it: there is one
//! per account, serving `org.freedesktop.secrets` on the account's own bus.
//! Starting a second daemon for the session would put two writers on the same
//! keyring files. So this process owns `org.freedesktop.secrets` on the
//! session's bus and relays every call to the real daemon on the account's
//! bus, and every signal back — one keyring, reachable from both places.
//!
//! It relays bodies as bytes, without knowing the API: a body is serialised
//! from an 8-byte-aligned start in every message, so its encoding does not
//! depend on the header it travels behind. Object paths are the daemon's own
//! on both sides, so nothing needs translating.
//!
//! Runs as the account (the keeper drops privileges before exec), for as
//! long as the session's bus exists.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use futures_util::StreamExt as _;
use zbus::message::Type;
use zbus::{Connection, MatchRule, Message, MessageStream};

const SECRETS: &str = "org.freedesktop.secrets";

/// A call the daemon has not answered in this long is not going to be; the
/// caller gets an error instead of hanging. Unlock prompts do not count
/// against it — the Secret Service answers `Unlock` at once with a prompt
/// object and reports the outcome later, as a signal.
const CALL_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn run(session_bus: &Path, account_bus: &Path) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build the bridge runtime")?
        .block_on(serve(session_bus, account_bus))
}

async fn connect(path: &Path) -> anyhow::Result<Connection> {
    zbus::connection::Builder::address(format!("unix:path={}", path.display()).as_str())?
        .build()
        .await
        .with_context(|| format!("connect to {}", path.display()))
}

async fn serve(session_bus: &Path, account_bus: &Path) -> anyhow::Result<()> {
    let session = connect(session_bus).await?;
    let account = connect(account_bus).await?;
    session
        .request_name(SECRETS)
        .await
        .with_context(|| format!("own {SECRETS} on {}", session_bus.display()))?;
    tracing::info!(
        session = %session_bus.display(),
        account = %account_bus.display(),
        "Secret Service relayed into the session"
    );

    let signals_rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(SECRETS)?
        .build();
    let mut signals = MessageStream::for_match_rule(signals_rule, &account, None).await?;
    let mut calls = MessageStream::from(&session);

    loop {
        tokio::select! {
            call = calls.next() => {
                // The session's bus is gone: so is the session.
                let Some(Ok(call)) = call else { return Ok(()) };
                if call.message_type() != Type::MethodCall {
                    continue;
                }
                let (session, account) = (session.clone(), account.clone());
                tokio::spawn(async move {
                    if let Err(error) = relay_call(&session, &account, &call).await {
                        tracing::debug!(error = format!("{error:#}"), "Secret Service call not relayed");
                    }
                });
            }
            signal = signals.next() => {
                let Some(Ok(signal)) = signal else { return Ok(()) };
                if let Err(error) = relay_signal(&session, &signal).await {
                    tracing::debug!(error = format!("{error:#}"), "Secret Service signal not relayed");
                }
            }
        }
    }
}

/// Copy `message`'s body into `builder`'s message.
fn with_body(builder: zbus::message::Builder<'_>, message: &Message) -> anyhow::Result<Message> {
    let body = message.body();
    anyhow::ensure!(
        body.data().fds().is_empty(),
        "a message carrying file descriptors is not relayed"
    );
    // SAFETY: the bytes and the signature come from one well-formed message,
    // and a D-Bus body's encoding does not depend on its header (it always
    // starts 8-byte aligned).
    unsafe { builder.build_raw_body(body.data().bytes(), body.signature().clone(), Vec::new()) }
        .context("rebuild the message")
}

async fn relay_call(session: &Connection, account: &Connection, call: &Message) -> anyhow::Result<()> {
    let header = call.header();
    let path = header.path().context("a method call without a path")?.to_owned();
    let member = header.member().context("a method call without a member")?.to_owned();
    let mut builder = Message::method_call(path, member)?.destination(SECRETS)?;
    if let Some(interface) = header.interface() {
        builder = builder.interface(interface.to_owned())?;
    }
    let forwarded = with_body(builder, call)?;
    let serial = forwarded.primary_header().serial_num();

    // Listen before sending, so the reply cannot slip past.
    let mut replies = MessageStream::from(account);
    account.send(&forwarded).await?;
    let reply = tokio::time::timeout(CALL_TIMEOUT, async {
        while let Some(Ok(message)) = replies.next().await {
            if message.header().reply_serial() == Some(serial) {
                return Some(message);
            }
        }
        None
    })
    .await;

    let answer = match reply {
        Ok(Some(reply)) if reply.message_type() == Type::MethodReturn => {
            with_body(Message::method_return(&header)?, &reply)?
        }
        Ok(Some(reply)) => {
            let name = reply
                .header()
                .error_name()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "org.freedesktop.DBus.Error.Failed".to_owned());
            with_body(Message::error(&header, name.as_str())?, &reply)?
        }
        Ok(None) | Err(_) => Message::error(&header, "org.freedesktop.DBus.Error.NoReply")?
            .build(&("the account's Secret Service did not answer",))?,
    };
    session.send(&answer).await?;
    Ok(())
}

async fn relay_signal(session: &Connection, signal: &Message) -> anyhow::Result<()> {
    let header = signal.header();
    let path = header.path().context("a signal without a path")?.to_owned();
    let interface = header.interface().context("a signal without an interface")?.to_owned();
    let member = header.member().context("a signal without a member")?.to_owned();
    let copy = with_body(Message::signal(path, interface, member)?, signal)?;
    session.send(&copy).await?;
    Ok(())
}
