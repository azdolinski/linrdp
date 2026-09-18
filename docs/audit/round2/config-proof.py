#!/usr/bin/env python3
from pathlib import Path
import subprocess,tempfile,itertools
root=Path(__file__).resolve().parents[3];deps=root/'target/debug/deps'
with tempfile.TemporaryDirectory(prefix='linrdp-audit2-config-') as td:
    source=Path(td)/'proof.rs';binary=Path(td)/'proof'
    source.write_text(Path(__file__).with_suffix('.rs.txt').read_text().replace('__REPO__',str(root)))
    names=['anyhow','serde','serde_norway','tracing']
    for libraries in itertools.product(*(sorted(deps.glob(f'lib{name}-*.rlib')) for name in names)):
        cmd=['rustc','--edition=2024',str(source),'-L',f'dependency={deps}']
        for name,lib in zip(names,libraries):
            cmd+=['--extern',f'{name}={lib}']
        result=subprocess.run(cmd+['-o',str(binary)],capture_output=True,text=True)
        if result.returncode==0:break
    else:raise SystemExit(result.stderr)
    subprocess.run([str(binary)],check=True)
