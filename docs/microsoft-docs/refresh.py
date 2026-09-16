#!/usr/bin/env python3
"""Pobiera/odswieza specyfikacje MS-RDP* z learn.microsoft.com.

PDF  -> [MS-X].pdf            (URL biezacej wersji, bez daty)
DOCX -> [MS-X]-YYMMDD.docx    (najnowsza datowana rewizja z listy na stronie)

Istniejace pliki sa pomijane; usun plik, zeby wymusic ponowne pobranie.
Liste dokumentow trzyma TARGETS ponizej (slug -> GUID strony na learn).
"""
import json, os, re, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

DEST = os.path.dirname(os.path.abspath(__file__))
CDN = "https://winprotocoldocs-bhdugrdyduf5h2e4.b02.azurefd.net"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) doc-fetch/1.0"}
TARGETS = json.loads(open(os.path.join(DEST, "targets.json")).read())


def get(url, timeout=300):
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def save(url, dst, magic=None):
    data = get(url)
    if magic and not data.startswith(magic):
        raise ValueError(f"unexpected content ({len(data)}B)")
    open(dst + ".part", "wb").write(data)
    os.replace(dst + ".part", dst)
    return len(data)


def latest_docx(slug):
    """Zwraca (data, url) najnowszego DOCX; pomija warianty -diff/-errata."""
    html = get(f"https://learn.microsoft.com/en-us/openspecs/windows_protocols/{slug}/{TARGETS[slug]}",
               timeout=90).decode("utf-8", "replace")
    up = slug.upper()
    rx = re.compile(r"%5b" + re.escape(up) + r"%5d-(\d{6})\.docx$", re.I)
    found = {}
    for link in set(re.findall(r"https://winprotocoldocs-[^\"'<>]+?\.docx", html)):
        m = rx.search(link)
        if m:
            found[m.group(1)] = link
    return (max(found), found[max(found)]) if found else (None, None)


def work(slug):
    up, msg = slug.upper(), []
    pdf = os.path.join(DEST, f"[{up}].pdf")
    if os.path.exists(pdf) and os.path.getsize(pdf) > 1024:
        msg.append("pdf=skip")
    else:
        try:
            msg.append(f"pdf={save(f'{CDN}/{up}/%5b{up}%5d.pdf', pdf, b'%PDF') // 1024}KB")
        except Exception as e:
            msg.append(f"pdf=FAIL({e})")
    try:
        date, url = latest_docx(slug)
        if not date:
            msg.append("docx=none")
        else:
            dst = os.path.join(DEST, f"[{up}]-{date}.docx")
            if os.path.exists(dst) and os.path.getsize(dst) > 1024:
                msg.append(f"docx=skip({date})")
            else:
                msg.append(f"docx={save(url, dst, b'PK') // 1024}KB({date})")
    except Exception as e:
        msg.append(f"docx=FAIL({e})")
    return f"{up:14s} " + " ".join(msg)


def main():
    only = [a.lower() for a in sys.argv[1:]]
    todo = sorted(k for k in TARGETS if not only or k in only)
    if not todo:
        sys.exit(f"nic nie pasuje do {only}; dostepne: {', '.join(sorted(TARGETS))}")
    with ThreadPoolExecutor(max_workers=5) as ex:
        for line in ex.map(work, todo):
            print(line, flush=True)


if __name__ == "__main__":
    main()
