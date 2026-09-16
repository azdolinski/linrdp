#!/usr/bin/env python3
"""Wyciaga plain text z pobranych .docx (specyfikacje MS-*) -> <slug>.txt

Jedna linia na akapit, w kolejnosci dokumentu; komorki tabel tez laduja
jako osobne linie (tak wygladaja istniejace ms-rdpbcgr.txt / ms-rdpea.txt).
Tylko stdlib - bez python-docx i pandoc.
"""
import os, re, sys, zipfile
import xml.etree.ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
DEST = os.path.dirname(os.path.abspath(__file__))

# Word wstawia twarde spacje w odwolaniach typu "section\u00a02.2.8", przez co
# zwykly grep "section 2.2.8" nic nie znajduje - normalizujemy je do ASCII.
# Mysliniki i cudzyslowy typograficzne zostawiamy, to prawdziwa tresc.
SPACES = dict.fromkeys(map(ord, "\u00a0\u2007\u2009\u200a\u202f"), " ")
SPACES.update(dict.fromkeys(map(ord, "\u00ad\u200b\ufeff"), None))
SPACES[0x2011] = "-"


def para_text(p):
    """Tekst akapitu: w:t + tabulatory; w:br/w:cr lamia linie w obrebie akapitu."""
    out = []
    for node in p.iter():
        tag = node.tag
        if tag == W + "t":
            out.append(node.text or "")
        elif tag == W + "tab":
            out.append("\t")
        elif tag in (W + "br", W + "cr"):
            out.append("\n")
        elif tag == W + "noBreakHyphen":
            out.append("-")
    return "".join(out).translate(SPACES)


HEADING = re.compile(r"^Heading([1-9])$")


def style_of(p):
    pr = p.find(W + "pPr")
    if pr is None:
        return None
    s = pr.find(W + "pStyle")
    return s.get(W + "val") if s is not None else None


def extract(docx_path):
    """Zwraca (tekst, liczba_ponumerowanych_naglowkow, lista_naglowkow_z_TOC)."""
    with zipfile.ZipFile(docx_path) as z:
        xml = z.read("word/document.xml")
    body = ET.fromstring(xml).find(W + "body")
    if body is None:
        raise ValueError("brak w:body")
    lines, headings, toc = [], [], []
    # Numery sekcji sa generowane przez Worda (numbering.xml) i NIE ma ich
    # w tekscie akapitu - odtwarzamy je licznikiem po poziomach HeadingN,
    # tak zeby "2.2.11.2.1" zostalo przy naglowku i dalo sie je wygrepowac.
    counters = [0] * 10
    for p in body.iter(W + "p"):
        style = style_of(p)
        text = para_text(p)
        m = HEADING.match(style or "")
        if m:
            lvl = int(m.group(1))
            counters[lvl] += 1
            for deeper in range(lvl + 1, 10):
                counters[deeper] = 0
            num = ".".join(str(counters[i]) for i in range(1, lvl + 1))
            first, sep, rest = text.partition("\n")
            text = f"{num}\t{first}" + (sep + rest if sep else "")
            headings.append((num, first.strip()))
        elif re.match(r"^TOC[1-9]$", style or ""):
            t = text.split("\t")
            if len(t) >= 2:
                toc.append((t[0].strip(), t[1].strip()))
        lines.extend(l.rstrip() for l in text.split("\n"))
    return "\n".join(lines), headings, toc


def main():
    args = sys.argv[1:]
    if args:
        docs = []
        for a in args:
            docs += [f for f in os.listdir(DEST)
                     if f.endswith(".docx") and a.lower() in f.lower()]
    else:
        docs = [f for f in os.listdir(DEST) if f.endswith(".docx")]
    if not docs:
        sys.exit(f"nie znaleziono .docx pasujacych do {args}")
    for f in sorted(set(docs)):
        m = re.match(r"\[(MS-[A-Z0-9]+)\]", f)
        if not m:
            print(f"POMIN {f} (nietypowa nazwa)")
            continue
        out = os.path.join(DEST, m.group(1).lower() + ".txt")
        try:
            text, headings, toc = extract(os.path.join(DEST, f))
        except Exception as e:
            print(f"BLAD  {f}: {e}")
            continue
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        # Spis tresci w dokumencie zawiera juz gotowe numery - uzywamy go
        # jako kontroli, czy odtworzona numeracja naglowkow sie zgadza.
        bad = [(h, t) for h, t in zip(headings, toc) if h[0] != t[0]]
        warn = ""
        if len(headings) != len(toc):
            warn = f"  UWAGA naglowki={len(headings)} != TOC={len(toc)}"
        elif bad:
            warn = f"  UWAGA {len(bad)} niezgodnych numerow (np. {bad[0][0][0]} vs TOC {bad[0][1][0]})"
        print(f"OK    {os.path.basename(out):18s} {len(text.splitlines()):6d} linii  "
              f"{len(text) // 1024:5d} KB  naglowkow={len(headings)}{warn}")


if __name__ == "__main__":
    main()
