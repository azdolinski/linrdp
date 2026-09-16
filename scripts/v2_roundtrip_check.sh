#!/usr/bin/env bash
# Round-trip check for the AVC444v2 dual-encoder wire format:
# decode both substreams (ffmpeg), recombine to 4:4:4 exactly the way
# FreeRDP's general_LumaToYUV444 + general_ChromaV2ToYUV444 read them,
# and measure the error against the reference planes written by the
# v2_roundtrip_writes_artifacts test.
set -euo pipefail

ffmpeg -v error -y -i /tmp/v2_luma.h264 -pix_fmt yuv420p -f rawvideo /tmp/v2_luma.yuv
ffmpeg -v error -y -i /tmp/v2_chroma.h264 -pix_fmt yuv420p -f rawvideo /tmp/v2_chroma.yuv

python3 - <<'EOF'
W = H = 640, 480
W, H = 640, 480
PW, PH = W, H
HW = PW // 2   # half width
QW = PW // 4   # quarter width

luma = open('/tmp/v2_luma.yuv', 'rb').read()
chroma = open('/tmp/v2_chroma.yuv', 'rb').read()
ref = open('/tmp/v2_ref.y444', 'rb').read()
frame_sz = PW * PH * 3 // 2
assert len(luma) >= frame_sz and len(chroma) >= frame_sz, (len(luma), len(chroma))
luma = luma[-frame_sz:]      # last (converged) frame
chroma = chroma[-frame_sz:]

ly = luma[: PW * PH]
lu = luma[PW * PH: PW * PH * 5 // 4]
lv = luma[PW * PH * 5 // 4:]
cy = chroma[: PW * PH]
cu = chroma[PW * PH: PW * PH * 5 // 4]
cv = chroma[PW * PH * 5 // 4:]

U444 = bytearray(PW * PH)
V444 = bytearray(PW * PH)

# B2/B3 (luma view): even rows, even columns.
for y in range(PH // 2):
    for x in range(HW):
        U444[2 * y * PW + 2 * x] = lu[y * HW + x]
        V444[2 * y * PW + 2 * x] = lv[y * HW + x]

# B4/B5 (chroma view Y): ALL rows, odd columns; left half U, right half V.
for y in range(PH):
    row = y * PW
    for x in range(HW):
        U444[row + 2 * x + 1] = cy[y * PW + x]
        V444[row + 2 * x + 1] = cy[y * PW + HW + x]

# B6-B9 (chroma view U/V planes): odd rows, even columns per 4-column group.
for y in range(PH // 2):
    dst_row = (2 * y + 1) * PW
    for x in range(QW):
        U444[dst_row + 4 * x + 0] = cu[y * HW + x]
        V444[dst_row + 4 * x + 0] = cu[y * HW + QW + x]
        U444[dst_row + 4 * x + 2] = cv[y * HW + x]
        V444[dst_row + 4 * x + 2] = cv[y * HW + QW + x]

ry = ref[: PW * PH]
ru = ref[PW * PH: PW * PH * 2]
rv = ref[PW * PH * 2:]

def mae(a, b):
    return sum(abs(p - q) for p, q in zip(a, b)) / len(a)

print(f"Y MAE: {mae(ry, ly):.2f}")
print(f"U MAE: {mae(ru, U444):.2f}")
print(f"V MAE: {mae(rv, V444):.2f}")

# Failure signatures of the live bug: channel/position mix-ups produce
# errors an order of magnitude above plain H.264 quantization noise.
ok = mae(ry, ly) < 4 and mae(ru, U444) < 6 and mae(rv, V444) < 6
print("ROUND-TRIP", "PASS" if ok else "FAIL")
EOF
