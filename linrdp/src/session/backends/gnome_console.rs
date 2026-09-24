//! The console's GNOME session, for `mstsc /admin` — the Windows way of
//! reaching the session at the physical desk rather than a session of one's
//! own, and only ever by the account logged in there.

use super::{BackendChoice, Binder, DesktopBackend, Login, Serves};
use crate::session::{gate, privilege};
use crate::wayland::mutter::{self, AttachOptions, GnomeSession};

pub(crate) const ID: &str = "gnome-console";

/// Why `/admin` is refused: whoever is at the console, it is not this account.
pub(crate) const NOT_AT_CONSOLE: &str = "this account is not the one logged in at the console";

pub(crate) struct GnomeConsole;

impl DesktopBackend for GnomeConsole {
    fn id(&self) -> &'static str {
        ID
    }

    fn describe(&self) -> &'static str {
        "the console's GNOME session (/admin)"
    }

    fn serves(&self) -> Serves {
        Serves::Console
    }

    fn choice(&self) -> Option<BackendChoice> {
        None
    }

    fn probe(&self, login: &Login<'_>) -> Result<Binder, String> {
        // Looked for on this account's own bus, so the only console that can
        // be found is this account's.
        let target = find(login.user).ok_or_else(|| NOT_AT_CONSOLE.to_owned())?;
        Ok(Box::new(move |login: &Login<'_>| bind(login, &target)))
    }
}

/// `user`'s running GNOME session — the one at the console — if this process
/// can reach it: a bus of theirs on which Mutter's remote desktop answers.
pub(crate) fn find(user: &str) -> Option<GnomeSession> {
    let ids = privilege::lookup_user(user).ok()?;
    mutter::find(ids.uid, ids.gid)
}

/// Attach this worker to the console's GNOME session.
///
/// Nothing is created and no PAM session is opened: the desktop exists and
/// belongs to the account that just authenticated — the probe that chose
/// this case found it on that account's own bus. The physical desk is kept
/// dark and the session locked again afterwards (see `AttachOptions::console`).
fn bind(login: &Login<'_>, target: &GnomeSession) -> anyhow::Result<()> {
    let user = login.user;
    // `session.fixed_size` pins the virtual monitor too.
    let size = login.fixed_size.unwrap_or(login.client_size);
    let ids = privilege::lookup_user(user)?;
    // The probe found a bus on which Mutter answers; that bus must belong to
    // this account, or the desktop is somebody else's.
    anyhow::ensure!(
        target.uid == ids.uid,
        "the GNOME session found for {user} belongs to uid {}, not {} — refusing to bind",
        target.uid,
        ids.uid
    );
    mutter::attach(user, target, AttachOptions::console(size), size)?;
    gate::bind_compositor("gnome", user, &target.runtime_dir.to_string_lossy(), size)?;
    tracing::info!(user, "routed to the user's GNOME session");
    Ok(())
}
