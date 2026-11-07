"""Decode every loose git object inside a zipped repo, in memory.

Nothing is extracted and git is never run, so no hook can fire.
Usage: python -I zip_git_objects.py <archive.zip>
"""
import sys
import zipfile
import zlib

z = zipfile.ZipFile(sys.argv[1])
for n in sorted(z.namelist()):
    if "/.git/objects/" not in n or n.endswith("/") or "/pack/" in n or "/info/" in n:
        continue
    raw = zlib.decompress(z.read(n))
    hdr, body = raw.split(b"\0", 1)
    sha = n.split("objects/")[1].replace("/", "")
    print("=====", sha, hdr.decode())
    if hdr.startswith(b"tree"):
        i = 0
        while i < len(body):  # entries: "<mode> <name>\0<20-byte sha>"
            sp = body.index(b" ", i)
            nul = body.index(b"\0", sp)
            print("   ", body[i:sp].decode(), body[sp + 1:nul].decode(), body[nul + 1:nul + 21].hex())
            i = nul + 21
    elif len(body) < 4000:
        print(body.decode("utf-8", "replace"))
    else:
        print("    magic:", body[:16])
