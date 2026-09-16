#!/usr/bin/env bash
# Round-trip check for the AVC444v2 wire format.
#
# Per MS-RDPEGFX 2.2.4.6 both subframes come from ONE encoder and are decoded
# by ONE decoder as one stream, so the artifact written by the
# v2_roundtrip_writes_artifacts test alternates: luma, chroma, luma, chroma…
# Decode it (ffmpeg), take the last converged luma/chroma pair, recombine to
# 4:4:4 exactly the way FreeRDP's general_LumaToYUV444 +
# general_ChromaV2ToYUV444 read them, and measure the error against the
# reference planes.
set -euo pipefail

ffmpeg -v error -y -i /tmp/v2_stream.h264 -pix_fmt yuv420p -f rawvideo /tmp/v2_stream.yuv

python3 - <<'EOF'
W, H = 640, 480
PW, PH = W, H
HW = PW // 2   # half width
QW = PW // 4   # quarter width

data = open('/tmp/v2_stream.yuv', 'rb').read()
ref = open('/tmp/v2_ref.y444', 'rb').read()
frame_sz = PW * PH * 3 // 2
n_frames = len(data) // frame_sz
assert n_frames >= 2, n_frames
# The stream is luma, chroma, luma, chroma… so the last pair is
# (second-to-last, last). An odd frame count would mean a dropped subframe.
assert n_frames % 2 == 0, f"odd frame count {n_frames}: a subframe went missing"
luma = data[(n_frames - 2) * frame_sz:(n_frames - 1) * frame_sz]
chroma = data[(n_frames - 1) * frame_sz:n_frames * frame_sz]

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
