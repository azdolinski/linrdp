#!/usr/bin/env python3
"""Execute the unchanged production poller initialization in a controlled fixture.
Not an X11/RDP integration test. Gate is already bound before on_ready, as in NLA.
"""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
source=(root/'linrdp/src/clipboard.rs').read_text()
start=source.index('                let mut display = start_display;')
end=source.index('                let mut last_text:',start)
initialization=source[start:end]
with tempfile.TemporaryDirectory(prefix='linrdp-audit3-poller-') as td:
    work=Path(td)
    (work/'proof.rs').write_text('''#![allow(unused_mut)]
mod session { pub mod gate { pub fn generation()->u64 { 1 } } }
fn main() {
 let start_display=String::from(":77");
 let start_xauthority=String::from("/fixture/ambient-cookie");
 // Backend was built before authentication. Router has now bound :88.
 unsafe { std::env::set_var("DISPLAY",":88"); std::env::set_var("XAUTHORITY","/fixture/session-cookie"); }
'''+initialization+'''
 assert_eq!(bound_at,session::gate::generation());
 assert_eq!(display,":77");
 assert_eq!(std::env::var("DISPLAY").unwrap(),":77");
 assert_eq!(std::env::var("XAUTHORITY").unwrap(),"/fixture/ambient-cookie");
 println!("T02 CONFIRMED: poller initialized with stale :77; gate generation already 1, so refresh branch is skipped; global DISPLAY/XAUTHORITY overwritten");
}
''')
    subprocess.run(['rustc','--edition=2024',str(work/'proof.rs'),'-o',str(work/'proof')],check=True)
    subprocess.run([str(work/'proof')],check=True,timeout=5)
