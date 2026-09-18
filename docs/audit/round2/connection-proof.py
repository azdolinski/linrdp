#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[3]
deps=root/'target/debug/deps'
server=sorted(deps.glob('libironrdp_server-*.rlib'),key=lambda p:p.stat().st_mtime,reverse=True)[0]
with tempfile.TemporaryDirectory(prefix='linrdp-audit2-connection-') as td:
    binary=Path(td)/'proof'
    for tokio in deps.glob('libtokio-*.rlib'):
        cmd=['rustc','--edition=2024',str(Path(__file__).with_suffix('.rs')),'-L',f'dependency={deps}','--extern',f'ironrdp_server={server}','--extern',f'tokio={tokio}','-o',str(binary)]
        result=subprocess.run(cmd,capture_output=True,text=True)
        if result.returncode==0:
            break
    else:
        raise SystemExit('No matching built tokio artifact. Build linrdp first.\n'+result.stderr)
    subprocess.run([str(binary)],check=True,timeout=5)
