"""Redact synthetic canaries and local paths from the 2026-11 raw results.

The harness writes a random CANARY-... value into each run's .env and may echo it
into sink.log/transcript.json/summary.md. Remove the .env files and replace the
canary with CANARY-REDACTED. Counts stay in runs.jsonl/sweep.jsonl; only the
human-readable evidence is redacted.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent
CANARY = re.compile(r"CANARY-[0-9a-fA-F]{8,}")
HOME = re.compile(r"C:\\+Users\\+krypt", re.IGNORECASE)
HOME_FWD = re.compile(r"C:/Users/krypt", re.IGNORECASE)
removed = 0
redacted = 0

for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    if path.name == ".env" and path.parent.name.startswith("sylenix-run-"):
        path.unlink()
        removed += 1
        continue
    if path.suffix.lower() not in {".json", ".jsonl", ".log", ".md", ".txt", ".csv"}:
        continue
    try:
        data = path.read_bytes()
    except OSError:
        continue
    text = None
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        continue
    new = CANARY.sub("CANARY-REDACTED", text)
    new = HOME.sub("<HOME>", new)
    new = HOME_FWD.sub("<HOME>", new)
    if new != text:
        path.write_text(new, encoding="utf-8", newline="\n")
        redacted += 1

(ROOT / "2026-11-sanitize.log").write_text(
    f"removed .env files: {removed}\nredacted text files: {redacted}\n", encoding="utf-8")
print(f"removed .env files: {removed}")
print(f"redacted text files: {redacted}")
