#!/usr/bin/env python3
"""Component proofs from current production source; no accounts, PAM or services changed.
The session proof drives a controlled late publisher, not a real keeper/PAM/X session.
"""
from pathlib import Path
import subprocess,tempfile,pwd,os
root=Path(__file__).resolve().parents[3]
deps=root/'target/debug/deps'
def between(path,start,end):
    text=(root/path).read_text(); a=text.index(start); return text[a:text.index(end,a)]
def compile_run(work,name,source,crates,args=()):
    path=work/(name+'.rs'); path.write_text(source)
    cmd=['rustc','--edition=2024',str(path),'-L',f'dependency={deps}','-o',str(work/name)]
    for crate in crates:
        lib=max(deps.glob('lib'+crate+'-*.rlib'),key=lambda p:p.stat().st_mtime)
        cmd+=['--extern',f'{crate}={lib}']
    subprocess.run(cmd,check=True)
    subprocess.run([str(work/name),*args],check=True,timeout=10)
with tempfile.TemporaryDirectory(prefix='linrdp-audit4-') as td:
    work=Path(td)
    # Exact source bodies, not reimplementations of the lock or wait logic.
    lock=between('linrdp/src/session/mod.rs','struct AccountLock {',"/// The user's session, creating one")
    attach=between('linrdp/src/session/mod.rs','pub(crate) fn attach_existing(', '/// Which display this connection serves.')
    wait=between('linrdp/src/session/keeper_main.rs','pub(crate) fn wait_for_record(', '#[cfg(test)]')
    source='''#![allow(dead_code)]
use std::path::Path;
use std::ops::RangeInclusive;
use anyhow::Context as _;
'''
    for module in ['privilege','registry','display_alloc']:
        source+=f'#[path="{root}/linrdp/src/session/{module}.rs"] mod {module};\n'
    source+=lock+attach+wait+r'''
fn record(user:&str,display:u16)->registry::SessionRecord {
 registry::SessionRecord{user:user.into(),display,runtime_dir:"fixture".into(),xauthority:"fixture".into(),locked:false,logind_id:None}
}
fn main()->anyhow::Result<()> {
 let args:Vec<_>=std::env::args().collect(); let base=Path::new(&args[1]); let user=&args[2];
 std::fs::create_dir(base)?;
 // Worker A holds account lock while starting keeper A. Keeper A owns a display lease.
 let account_a=AccountLock::acquire(base,user)?;
 let lease_a=display_alloc::allocate(base,51000..=51001)?;
 assert!(wait_for_record(base,lease_a.number,user,std::time::Duration::from_millis(1)).is_err());
 // Production create() returns the timeout; its caller releases AccountLock.
 // The detached keeper still owns lease_a and has not published a record.
 drop(account_a);
 let account_b=AccountLock::acquire(base,user)?;
 assert!(attach_live(base,user,51000..=51001).is_none());
 let lease_b=display_alloc::allocate(base,51000..=51001)?;
 assert_ne!(lease_a.number,lease_b.number);
 registry::write_record(base,&record(user,lease_b.number))?;
 drop(account_b);
 // Late completion of keeper A, after B has made its own session.
 registry::write_record(base,&record(user,lease_a.number))?;
 assert!(!is_stale(base,lease_a.number)); assert!(!is_stale(base,lease_b.number));
 assert_eq!(registry::read_one(base,lease_a.number).unwrap().user,registry::read_one(base,lease_b.number).unwrap().user);
 println!("U02 CONFIRMED (controlled lifecycle): timeout released account lock; two live display leases and two records for one UID");
 Ok(())
}
'''
    compile_run(work,'session',source,['anyhow','libc','tracing'],[str(work/'state'),pwd.getpwuid(os.getuid()).pw_name])
    getter=between('linrdp/src/clipboard.rs','pub(crate) fn x11_get_text(', '/// Parse an `x-special')
    source=getter+r'''
fn main() {
 // Request callback captured this pair immediately before handover.
 let old_display=":51001"; let old_cookie="/fixture/greeter-cookie";
 // Greeter thread completes bind before the request calls x11_get_text.
 unsafe { std::env::set_var("DISPLAY",":51000"); std::env::set_var("XAUTHORITY","/fixture/session-cookie"); }
 let _ = x11_get_text(old_display,old_cookie);
 assert_eq!(std::env::var("DISPLAY").unwrap(),old_display);
 assert_eq!(std::env::var("XAUTHORITY").unwrap(),old_cookie);
 println!("U01 CONFIRMED: production text getter restores stale DISPLAY/XAUTHORITY after handover; no X server needed");
}
'''
    compile_run(work,'clipboard',source,['arboard'])
