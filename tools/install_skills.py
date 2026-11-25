from __future__ import annotations
import argparse
import shutil
from pathlib import Path

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    src = Path(__file__).resolve().parents[1] / "skills"
    destination = Path(args.dest).expanduser().resolve()
    for skill in sorted(src.iterdir()):
        target = destination / skill.name
        if target.exists():
            raise SystemExit("Existing skill refused: " + skill.name)
        if not args.dry_run:
            shutil.copytree(skill, target)
        print(skill.name)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
