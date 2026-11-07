"""Self-check for olivebloom.yar (needs: pip install yara-python).

Run from the repo root: python -I iocs/test_yara.py
"""
import io
import sys
import zipfile

import yara

rules = yara.compile("iocs/olivebloom.yar")
hook = open("evidence/post-checkout.defanged.txt", encoding="utf-8").read().split("-" * 80 + "\n", 1)[1]


def zipped(*names):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for n in names:
            z.writestr(n, "x")
    return b.getvalue()


cases = [
    ("dropper hook", hook.encode(), {"OliveBloom_PostCheckout_Dropper"}),
    ("benign hook", b'#!/bin/sh\nexec git lfs post-checkout "$@"\n', set()),
    ("zip with live hook", zipped("r/readme.md", "r/.git/hooks/pre-commit.sample", "r/.git/hooks/post-checkout"), {"Zip_Ships_Live_Git_Hook"}),
    ("zip with samples only", zipped("r/.git/hooks/post-checkout.sample", "r/.git/hooks/pre-push.sample"), set()),
    ("zip without git", zipped("a/b.txt"), set()),
]
failed = 0
for name, data, want in cases:
    got = {m.rule for m in rules.match(data=data)}
    failed += got != want
    print("PASS" if got == want else "FAIL", name, sorted(got))
sys.exit(failed)
