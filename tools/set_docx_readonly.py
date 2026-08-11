#!/usr/bin/env python3
"""Apply Word's non-password read-only document protection to a DOCX."""

from __future__ import annotations

import argparse
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
ET.register_namespace("w", W_NS)


def protect(input_path: Path, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(input_path, "r") as source:
        settings = ET.fromstring(source.read("word/settings.xml"))
        tag = f"{{{W_NS}}}documentProtection"
        for existing in list(settings):
            if existing.tag == tag:
                settings.remove(existing)
        protection = ET.Element(tag)
        protection.set(f"{{{W_NS}}}edit", "readOnly")
        protection.set(f"{{{W_NS}}}enforcement", "1")
        protection.set(f"{{{W_NS}}}formatting", "0")
        settings.insert(0, protection)
        settings_bytes = ET.tostring(settings, encoding="UTF-8", xml_declaration=True)

        with tempfile.NamedTemporaryFile(prefix="filesentry-readonly-", suffix=".docx", dir=output_path.parent, delete=False) as temp:
            temporary_path = Path(temp.name)
        try:
            with zipfile.ZipFile(temporary_path, "w", zipfile.ZIP_DEFLATED) as target:
                for info in source.infolist():
                    if info.filename == "word/settings.xml":
                        target.writestr(info, settings_bytes)
                    else:
                        target.writestr(info, source.read(info.filename))
            temporary_path.replace(output_path)
        finally:
            if temporary_path.exists():
                temporary_path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_docx", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    protect(args.input_docx, args.out)
    print(f"[OK] wrote {args.out} (mode=readOnly)")


if __name__ == "__main__":
    main()
