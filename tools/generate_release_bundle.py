"""Create the user guide and provenance certificate for a Sentinel build."""

from __future__ import annotations

import argparse
import hashlib
import html
from datetime import datetime, timezone
from pathlib import Path


PRODUCT_NAME = "FileSentry Sentinel"
GUIDE_NAME = "FileSentrySentinel_User_Guide.md"
CERTIFICATE_NAME = "FileSentrySentinel_Exclusive_Build_Certificate.html"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def atomic_text(path: Path, value: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(value, encoding="utf-8", newline="\n")
    temporary.replace(path)


def create_guide(source: Path, destination: Path) -> str:
    content = source.read_text(encoding="utf-8").replace("FileSentry.exe", "FileSentrySentinel.exe")
    prefix = (
        "# FileSentry Sentinel — User Guide\n\n"
        "Tài liệu đi kèm bản build hiện tại. Dữ liệu, mật khẩu và nhật ký của ứng dụng "
        "không được ghi vào tài liệu này.\n\n"
    )
    atomic_text(destination, prefix + content)
    return sha256(destination)


def create_certificate(destination: Path, *, owner: str, build_id: str, built_at: str, exe_hash: str, guide_hash: str) -> None:
    values = {
        "owner": html.escape(owner),
        "build_id": html.escape(build_id),
        "built_at": html.escape(built_at),
        "exe_hash": html.escape(exe_hash),
        "guide_hash": html.escape(guide_hash),
    }
    document = f"""<!doctype html>
<html lang="vi"><head><meta charset="utf-8">
<title>{PRODUCT_NAME} — Build Certificate</title>
<style>
:root {{ color-scheme: dark; }} body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#07111f; color:#f8fafc; font-family:Segoe UI,Arial,sans-serif; }}
.certificate {{ width:min(860px,88vw); padding:52px 58px; background:linear-gradient(145deg,#10243b,#0b1729); border:1px solid #315574; box-shadow:0 24px 70px #0008; position:relative; }}
.certificate:before {{ content:""; position:absolute; inset:13px; border:1px solid #38bdf855; pointer-events:none; }}
.brand {{ color:#38bdf8; letter-spacing:.18em; font-size:12px; font-weight:700; }} h1 {{ margin:18px 0 6px; font-size:34px; }} .subtitle {{ color:#a8b8cb; font-size:15px; }}
.ribbon {{ display:inline-block; margin:32px 0 24px; padding:10px 16px; background:#103622; color:#22c55e; border:1px solid #22c55e88; font-weight:700; letter-spacing:.08em; font-size:12px; }}
.grid {{ display:grid; grid-template-columns:180px 1fr; gap:12px 24px; padding:22px 0; border-top:1px solid #244360; border-bottom:1px solid #244360; }}
.label {{ color:#6f849d; font-size:12px; text-transform:uppercase; letter-spacing:.08em; }} .value {{ color:#f8fafc; font-size:14px; word-break:break-word; }}
.hash {{ color:#7dd3fc; font-family:Consolas,monospace; font-size:12px; }} .foot {{ margin-top:28px; color:#91a4bc; font-size:12px; line-height:1.6; }}
.disclaimer {{ margin-top:18px; color:#fbbf24; font-size:11px; line-height:1.5; }}
</style></head><body><main class="certificate">
<div class="brand">FILESENTRY SENTINEL / LOCAL RELEASE IDENTITY</div>
<h1>Build Provenance Certificate</h1><div class="subtitle">Chứng nhận nhận diện bản build nội bộ và tính toàn vẹn artefact</div>
<div class="ribbon">EXCLUSIVE LOCAL BUILD RECORD</div><section class="grid">
<div class="label">Sản phẩm</div><div class="value">{PRODUCT_NAME}</div>
<div class="label">Chủ sở hữu khai báo</div><div class="value">{values["owner"]}</div>
<div class="label">Mã build duy nhất</div><div class="value">{values["build_id"]}</div>
<div class="label">Thời điểm UTC</div><div class="value">{values["built_at"]}</div>
<div class="label">SHA-256 EXE</div><div class="value hash">{values["exe_hash"]}</div>
<div class="label">SHA-256 hướng dẫn</div><div class="value hash">{values["guide_hash"]}</div>
</section><div class="foot">Artefacts: <strong>FileSentrySentinel.exe</strong> và <strong>{GUIDE_NAME}</strong>.</div>
<div class="disclaimer">Đây là chứng nhận provenance nội bộ do script build tạo ra, không phải chứng chỉ pháp lý, chứng nhận bản quyền/nhãn hiệu hoặc chữ ký số của cơ quan cấp chứng thư.</div>
</main></body></html>
"""
    atomic_text(destination, document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--guide-source", type=Path, required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--owner", default="Local Project Owner")
    args = parser.parse_args()
    exe = args.exe.resolve(strict=True)
    guide_source = args.guide_source.resolve(strict=True)
    dist = args.dist.resolve(strict=False)
    dist.mkdir(parents=True, exist_ok=True)
    guide = dist / GUIDE_NAME
    certificate = dist / CERTIFICATE_NAME
    guide_hash = create_guide(guide_source, guide)
    exe_hash = sha256(exe)
    now = datetime.now(timezone.utc)
    built_at = now.isoformat(timespec="seconds")
    build_id = f"FS-SENTINEL-{now:%Y%m%d%H%M%S}-{exe_hash[:12]}"
    create_certificate(certificate, owner=str(args.owner).strip() or "Local Project Owner", build_id=build_id, built_at=built_at, exe_hash=exe_hash, guide_hash=guide_hash)
    print(f"Release guide: {guide}")
    print(f"Build certificate: {certificate}")
    print(f"Build ID: {build_id}")
    print(f"EXE SHA-256: {exe_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
