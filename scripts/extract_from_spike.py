#!/usr/bin/env python3
"""Write the files embedded in section 8 of POC_SPIKE.md to disk, verbatim.

Run once from the repository root. It refuses to overwrite existing files unless
you pass --force, because after Wave 0 the repository files are the source of
truth and POC_SPIKE.md section 8 is only a snapshot.
"""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
text = (root / "POC_SPIKE.md").read_text()
blocks = re.findall(r"### 8\.\d+ `([^`]+)`\n\n```[a-z]*\n(.*?)\n```", text, re.S)
if len(blocks) != 8:
    sys.exit(f"expected 8 embedded files in POC_SPIKE.md section 8, found {len(blocks)}")

force = "--force" in sys.argv
existing = [rel for rel, _ in blocks if (root / rel).exists()]
if existing and not force:
    sys.exit("refusing to overwrite existing files (use --force): " + ", ".join(existing))

for rel, body in blocks:
    dest = root / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(body + "\n")
    print("wrote", rel)
