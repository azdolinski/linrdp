#!/usr/bin/env python3
"""Exercise the real PAM loader with an incomplete library in a child only."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parents[3]
with tempfile.TemporaryDirectory(prefix='linrdp-audit3-pam-') as td:
    work=Path(td)
    # pam_getenvlist deliberately absent; all required auth functions exist.
    (work/'fake.c').write_text('''
int pam_start(void*a,void*b,void*c,void*d){return 4;}
int pam_authenticate(void*a,int b){return 7;}
int pam_acct_mgmt(void*a,int b){return 7;}
int pam_end(void*a,int b){return 0;}
int pam_setcred(void*a,int b){return 0;}
int pam_open_session(void*a,int b){return 0;}
int pam_close_session(void*a,int b){return 0;}
''')
    subprocess.run(['cc','-shared','-fPIC',str(work/'fake.c'),'-o',str(work/'libpam.so.0')],check=True)
    (work/'proof.rs').write_text('''#![allow(dead_code)]
#[path="'''+str(root/'linrdp/src/pam.rs')+'''"] mod pam;
fn main() {
 let result=pam::authenticate("audit-fixture", "unused");
 match result {
  Err(pam::NoVerdict::NotInstalled(ref reason)) => {
   assert!(reason.contains("pam_getenvlist"));
   println!("T03 CONFIRMED: installed but incomplete PAM classified as NotInstalled: {reason}");
  }, other => panic!("unexpected {other:?}"),
 }
}
''')
    subprocess.run(['rustc','--edition=2024',str(work/'proof.rs'),'-o',str(work/'proof')],check=True)
    subprocess.run([str(work/'proof')],env={**os.environ,'LD_LIBRARY_PATH':str(work)},check=True,timeout=5)
