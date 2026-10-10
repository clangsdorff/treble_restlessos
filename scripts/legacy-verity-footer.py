#!/usr/bin/env python3
"""generate a legacy android-verity footer for devices whose vendor first-stage
mount builds an android-verity dm target (dm-android-verity.c) but whose GSI
image carries no verity metadata footer.

the driver reads VERITY_METADATA_SIZE (8KiB) from the tail of the block device
named in the dm table (the system partition) and parses:

    struct android_metadata_header {
        le32 magic_number;      # 0xb001b001, or 0x46464f56 ("VOFF") = disabled
        le32 protocol_version;  # 0
        u8   signature[256];    # unused in the disabled path
        le32 table_length;
    }                           # followed by the verity table ascii string

a footer carrying the DISABLE magic maps the system partition as a plain linear
device - no signature check, no real verity table. the table string only has to
tokenise into VERITY_TABLE_ARGS (10) fields.

usage:
    legacy-verity-footer.py footer.bin
    # then from a recovery that can see the partition:
    #   dd if=footer.bin of=/dev/block/by-name/system_a \
    #       seek=$(( $(blockdev --getsize64 /dev/block/by-name/system_a) / 4096 - 2 )) \
    #       bs=4096 count=2 conv=notrunc
"""

import struct
import sys

MAGIC_DISABLE = 0x46464F56
VERSION = 0
METADATA_SIZE = 8 * 1024
HEADER_SIZE = 4 + 4 + 256 + 4

# 10 tokens: the count dm-android-verity requires from the verity table
TABLE = "1 vroot none none 0 8192 1 sha256 pad pad"

def build() -> bytes:
    blob = bytearray(METADATA_SIZE)
    table = TABLE.encode()
    blob[0:4] = struct.pack("<I", MAGIC_DISABLE)
    blob[4:8] = struct.pack("<I", VERSION)
    # signature: 256 zero bytes, not verified on the disabled path
    blob[264:268] = struct.pack("<I", len(table))
    blob[268:268 + len(table)] = table
    return bytes(blob)

def selfcheck(blob: bytes) -> None:
    magic, ver = struct.unpack("<II", blob[:8])
    (tlen,) = struct.unpack("<I", blob[264:268])
    assert magic == MAGIC_DISABLE
    assert ver == VERSION
    assert 0 < tlen <= METADATA_SIZE - HEADER_SIZE
    table = blob[268:268 + tlen].decode()
    assert len(table.split()) >= 10

if __name__ == "__main__":
    blob = build()
    selfcheck(blob)
    out = sys.argv[1] if len(sys.argv) > 1 else "verity-footer.bin"
    try:
        with open(out, "wb") as f:
            f.write(blob)
    except OSError as e:
        sys.exit(f"cannot write {out}: {e}")
    print(f"wrote {out} ({METADATA_SIZE} bytes); dd to the last 8KiB of the system partition")
