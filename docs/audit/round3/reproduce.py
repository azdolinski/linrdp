#!/usr/bin/env python3
"""Compile production modules; privileged run touches only temporary fixtures."""
from pathlib import Path
import os, pwd, subprocess, tempfile
root=Path(__file__).resolve().parents[3]
user=pwd.getpwuid(os.getuid()).pw_name
if os.getuid()==0:
    user=os.environ.get('SUDO_USER','user')
with tempfile.TemporaryDirectory(prefix='linrdp-audit3-build-') as td:
    work=Path(td)
    # The exec helper must still access its executable after dropping UID.
    work.chmod(0o755)
    source=(Path(__file__).parent/'component-proof.rs.txt').read_text().replace('__REPO__',str(root))
    (work/'proof.rs').write_text(source)
    deps=root/'target/debug/deps'
    cmd=['rustc','--edition=2024',str(work/'proof.rs'),'-L',f'dependency={deps}']
    for crate in ['anyhow','libc','tracing']:
        library=sorted(deps.glob(f'lib{crate}-*.rlib'))[0]
        cmd+=['--extern',f'{crate}={library}']
    cmd+=['-o',str(work/'proof')]
    subprocess.run(cmd,check=True,cwd=root)
    run=[str(work/'proof'),user]
    if os.getuid()!=0:
        run=['sudo','-n',*run]
    subprocess.run(run,check=True,cwd=root,timeout=30)
