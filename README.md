# FileSentry Sentinel

**FileSentry Sentinel** is the professional product name. Existing module names,
`FileSentry` data folders and service profile paths remain supported for
backward compatibility.

## Product identity and build output

- Product name: `FileSentry Sentinel`
- Windows executable: `dist\FileSentrySentinel.exe`
- Icon: `assets\filesentry-sentinel.ico` (vector source: `assets\filesentry-sentinel.svg`)
- UX/UI: enterprise dark console with status pills, non-blocking toast notifications, themed confirmation/input dialogs and step-by-step guide rail.
- Build output: thư mục `dist` chỉ giữ đúng 3 file: `FileSentrySentinel.exe`, `FileSentrySentinel_User_Guide.docx` và `FileSentrySentinel_Exclusive_Build_Certificate.docx`; thư mục tạm PyInstaller/spec được dọn sau build.
- `FileSentrySentinel_User_Guide.docx` là tài liệu cho người dùng cuối, có hình minh họa, sơ đồ luồng, bảng trạng thái và xử lý sự cố.
- `FileSentrySentinel_Exclusive_Build_Certificate.docx` là chứng chỉ nhận diện sở hữu nội bộ, chỉ hiển thị thông tin cần thiết cho người dùng; build script đặt chế độ Word Read Only cho file này.

FileSentry là MVP desktop chạy local trên Windows để theo dõi các khu vực file do người dùng chọn, phát hiện thay đổi bất thường, quản lý quarantine và ghi nhật ký hoạt động.

## Trạng thái phát hành

Workspace hiện là nền tảng **V1 — Local Defensive Console**. V1 tập trung vào
phát hiện, cảnh báo, audit, cách ly mã hóa và quản lý policy cục bộ. V2 mới bổ
sung Windows Service + Filesystem Minifilter để chặn I/O từ bên ngoài giao diện.

## Tính năng hiện có

- Giao diện desktop dark theme bằng Tkinter.
- Hệ thống hướng dẫn popup từng bước cho lần đầu và từng màn hình.
- Tài khoản admin cài sẵn cho lần khởi tạo đầu tiên.
- Bắt buộc đổi mật khẩu sau lần đăng nhập đầu.
- Bật/tắt bảo vệ và tạm dừng theo thời gian.
- Phiên xác thực trong bộ nhớ 15 phút cho thao tác thường; thao tác rủi ro cao vẫn yêu cầu nhập mật khẩu mới.
- Khóa quyền vào khu vực bảo vệ trong thời gian giới hạn.
- Media Guard cho camera/microphone: khóa, mở, khóa tạm thời và danh sách website origin.
- Media Library cho ảnh/video/âm thanh: đồng bộ toàn bộ ổ đĩa, tự cập nhật file thêm/sửa/xóa/đổi tên, khóa xóa riêng từng file và đưa file vào Kho riêng mã hóa để chặn đọc/sao chép từ bên ngoài.
- Access Center với phiên mở khóa camera/mic trong bộ nhớ, tự hết hạn và watcher khóa lại khi thay đổi ngoài ứng dụng.
- Include/exclude nhiều thư mục.
- Folder Lock bằng Windows ACL: lưu DACL gốc mã hóa trước khi khóa, khôi phục chính xác khi mở khóa, kiểm tra thay đổi ACL và tự mở khóa bắt buộc trước khi gỡ ứng dụng.
- Theo dõi file bằng `watchdog`; có polling fallback nếu chưa cài watchdog.
- SQLite WAL lưu event, cảnh báo và audit log.
- Cảnh báo đổi tên/xóa/tạo file hàng loạt.
- Nhận diện đuôi kép như `invoice.pdf.exe`.
- Kho mã hóa per-file/chunk, không ghi đè khi khôi phục.
- Chuỗi log hash-chain mã hóa để phát hiện sửa hoặc sắp xếp lại bằng chứng.
- Inventory read-only cho Registry Run/RunOnce, Startup folder và Scheduled Task.
- Kiểm tra posture antivirus/EDR cục bộ qua Windows Defender/Security Center.
- Xuất báo cáo sự cố `.fsreport` được mã hóa, gồm timeline và posture hiện tại.
- Metadata app/database/vault version được lưu mã hóa để chuẩn bị migration an toàn.
- Bảng kết nối TCP/UDP cục bộ và chỉ báo kết nối Internet bất thường.
- Gỡ bản EXE hai pha, có xác thực và lựa chọn xóa dữ liệu cục bộ.
- Quarantine có thể khôi phục.

## Chạy thử

```powershell
python -m pip install -r requirements.txt
python main.py
```

Để build bản Windows yêu cầu Administrator ngay khi khởi chạy:

```powershell
.\build.ps1
```

Có thể ghi tên chủ sở hữu vào chứng nhận build nội bộ:

```powershell
.\build.ps1 -OwnerName "Tên chủ sở hữu"
```

Nếu máy có nhiều Python, chỉ định runtime có `python-docx` để tạo tài liệu Word:

```powershell
.\build.ps1 -PythonPath ".\.venv\Scripts\python.exe" -DocsPythonPath "C:\đường\dẫn\python.exe"
```

Bản `.exe` dùng manifest `requireAdministrator`. Windows vẫn có thể hiển thị UAC theo chính sách bảo mật của máy; ứng dụng không tự bypass UAC.

Trong workspace Codex có thể chạy nhanh:

```powershell
.\run.ps1
```

Nếu muốn lưu dữ liệu tại vị trí riêng:

```powershell
$env:FILESENTRY_DATA_DIR = "C:\\ProgramData\\FileSentry"
python main.py
```

## Tài khoản khởi tạo

```text
Username: admin
Password: FileSentry@2026!
```

Đây là mật khẩu tạm thời cho bản MVP. Ứng dụng bắt buộc đổi mật khẩu ở lần đăng nhập đầu tiên.

## Tài liệu

- [Hướng dẫn người dùng](docs/USER_GUIDE.md)
- [Thiết kế kỹ thuật](docs/TECHNICAL_DESIGN.md)
- [Mô hình bảo mật V1](docs/SECURITY_MODEL.md)
- [Lộ trình V1 / V2 / Advanced](docs/RELEASE_PLAN.md)
- [Đối chiếu trạng thái triển khai](docs/IMPLEMENTATION_STATUS.md)
- [Theo dõi xử lý review bảo mật](docs/SECURITY_REVIEW_FOLLOWUP.md)

## Giới hạn MVP

FileSentry chưa phải antivirus/EDR, không chặn tuyệt đối file I/O ở kernel-mode, không xác định chắc chắn process gây ra từng file event và không tự chặn kết nối mạng ở V1. Network Guard chỉ đọc socket table cục bộ, không quét cổng, không DNS, không upload. Media Guard/Access Center dùng Windows policy và mô hình watch-and-revert có độ trễ polling; website origin là dữ liệu dành cho browser extension, chưa tự enforce URL trong browser. Nội dung cấu hình, xác thực, log/audit, vault, version metadata và quarantine được mã hóa; metadata SQLite như schema/row ID vẫn có thể nhìn thấy nếu mở database trực tiếp.
