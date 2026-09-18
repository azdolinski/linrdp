#!/usr/bin/env python3
"""Safe local component proofs; only temporary sentinel files are modified."""
from pathlib import Path
import subprocess
import tempfile
root = Path(__file__).resolve().parents[2]
deps = root / 'target/debug/deps'
with tempfile.TemporaryDirectory(prefix='linrdp-audit-build-') as td:
    work = Path(td)
    source = (Path(__file__).parent / 'proof-template.rs.txt').read_text()
    source = source.replace('__REPO__', str(root))
    # Always take the current function, so this proof can detect its repair.
    production = (root / 'linrdp/src/session/keeper_main.rs').read_text()
    begin = production.index('pub(crate) fn wait_for_record(')
    end = production.index('\n#[cfg(test)]', begin)
    old_begin = source.index('pub(crate) fn wait_for_record(')
    old_end = source.index('\nfn main()', old_begin)
    source = source[:old_begin] + production[begin:end] + source[old_end:]
    (work / 'proof.rs').write_text(source)
    command = ['rustc', '--edition=2024', str(work/'proof.rs'), '-L', f'dependency={deps}']
    for crate in ['anyhow', 'libc']:
        candidates = sorted(deps.glob(f'lib{crate}-*.rlib'))
        if not candidates:
            raise SystemExit('First build the project with cargo test -p linrdp --offline --no-default-features')
        command += ['--extern', f'{crate}={candidates[0]}']
    command += ['-o', str(work/'proof')]
    subprocess.run(command, check=True, cwd=root)
    subprocess.run([str(work/'proof')], check=True, cwd=root)
