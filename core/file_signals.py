"""Conservative, local file risk signals for the V1 monitor.

These are indicators, not malware verdicts.  The module intentionally avoids
executing or uploading files and reads only a small prefix when a signature is
useful.
"""

from __future__ import annotations

from pathlib import Path


EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".com", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".wsh", ".hta", ".lnk", ".chm",
}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta"}
MACRO_EXTENSIONS = {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm"}
DOCUMENT_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".zip"}


def _has_executable_suffix(path: Path) -> bool:
    return path.suffix.lower() in EXECUTABLE_EXTENSIONS


def _has_double_extension(path: Path) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    return len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTENSIONS and suffixes[-2] in DOCUMENT_EXTENSIONS


def _has_embedded_pe(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"MZ" and path.suffix.lower() not in {".exe", ".dll", ".sys", ".scr", ".cpl"}
    except OSError:
        return False


def analyze_file(path: str | Path) -> list[dict[str, str]]:
    """Return explainable risk indicators without changing the file."""

    candidate = Path(path)
    name = candidate.name
    lower_name = name.lower()
    suffix = candidate.suffix.lower()
    signals: list[dict[str, str]] = []

    if "\u202e" in name:
        signals.append({"code": "rtl_filename", "title": "Tên file dùng ký tự đảo chiều", "severity": "warning"})
    if _has_double_extension(candidate):
        signals.append({"code": "double_extension", "title": "File có đuôi kép đáng chú ý", "severity": "warning"})
    if suffix in SCRIPT_EXTENSIONS:
        signals.append({"code": "script_file", "title": "File script có thể thực thi", "severity": "warning"})
    if suffix in MACRO_EXTENSIONS:
        signals.append({"code": "macro_document", "title": "Tài liệu có thể chứa macro", "severity": "warning"})
    if suffix in {".iso", ".img", ".vhd", ".vhdx"}:
        signals.append({"code": "mounted_image", "title": "File ảnh đĩa có thể chứa nội dung thực thi", "severity": "warning"})
    if _has_executable_suffix(candidate) and suffix in {".lnk", ".chm", ".hta"}:
        signals.append({"code": "execution_container", "title": "File có cơ chế gọi nội dung thực thi", "severity": "warning"})
    if _has_embedded_pe(candidate):
        signals.append({"code": "embedded_pe", "title": "File có chữ ký PE nhưng đuôi không phải file thực thi", "severity": "critical"})
    if lower_name.endswith(".zip"):
        try:
            if candidate.stat().st_size > 512 * 1024 * 1024:
                signals.append({"code": "oversized_archive", "title": "Archive có kích thước rất lớn", "severity": "warning"})
        except OSError:
            pass
    return signals

