# FileSentry — Lộ trình V1 / V2 / Advanced

## Nguyên tắc an toàn

FileSentry là phần mềm phòng thủ cục bộ. Mặc định không gửi dữ liệu, file,
mật khẩu, nhật ký hoặc danh sách khu vực ra Internet. Không có chế độ điều
khiển từ xa trong V1.

Không có phần mềm nào có thể cam kết tuyệt đối không bị tấn công. Mục tiêu
thiết kế là giảm bề mặt tấn công, fail-closed khi kiểm tra bảo mật thất bại,
không lưu mật khẩu rõ, không đưa bí mật vào kernel driver và không để UI có
quyền cao hơn mức cần thiết.

## V1 — Local Defensive Console

Phạm vi mục tiêu: khoảng 50–70 đầu mục cốt lõi, tập trung vào file/Windows.

- Theo dõi include/exclude bằng watchdog hoặc polling fallback.
- Phát hiện tạo, sửa, xóa, đổi tên và thay đổi hàng loạt.
- Cảnh báo ransomware theo hành vi và nhận diện tên file đáng ngờ.
- Cách ly file bằng AES-GCM, manifest có xác thực và khôi phục có kiểm tra hash.
- Kho mã hóa per-file/chunk với manifest mã hóa, kiểm tra hash và khôi phục không ghi đè.
- Đăng nhập quản trị, bắt buộc đổi mật khẩu khởi tạo, chống brute-force tạm thời.
- Mã hóa cấu hình, xác thực, audit, cảnh báo và nội dung sự kiện.
- Ghi file nguyên tử, giới hạn kích thước dữ liệu giải mã, chống path traversal và
  symbolic link trong các thao tác nhạy cảm.
- Điều khiển camera/microphone ở mức Windows privacy policy khi hệ điều hành hỗ trợ.
- Network Guard local-only: bảng TCP/UDP, process/PID và chỉ báo kết nối ra ngoài
  bất thường; không port scan, DNS hoặc upload.
- Inventory read-only Registry/Startup/Scheduled Task, AV/EDR posture cục bộ và
  encrypted incident report có timeline.
- Hash-chain mã hóa để phát hiện sửa, chèn hoặc sắp xếp lại event/alert/audit.
- Popup hướng dẫn từng bước cho các màn hình chính.

Giới hạn bắt buộc của V1: monitor ở user mode không thể chặn đáng tin cậy mọi
thao tác từ Explorer hoặc một tiến trình khác trước khi file I/O xảy ra. V1 là
phát hiện/cảnh báo/cách ly có kiểm soát, không phải antivirus/EDR hay driver.

## V2 — Windows Enforcement

Phạm vi mục tiêu: khoảng 100–120 đầu mục, trong đó nhiều mục có thể phòng ngừa,
phát hiện và khắc phục.

- `FileSentryService` chạy nền, không hiển thị UI.
- UI/tray giao tiếp với service bằng Named Pipe có ACL, nonce, timeout và
  xác thực hai chiều; không gửi mật khẩu vào driver.
- Filesystem Minifilter đã ký để kiểm soát create/write/delete/rename trong
  protected roots.
- Token truy cập ngắn hạn theo đường dẫn, tiến trình, người dùng và thời hạn;
  mặc định từ chối khi policy hoặc service không xác định.
- Snapshot/rollback an toàn và recovery journal.
- Liên kết sự kiện với process bằng Windows telemetry để cảnh báo có ngữ cảnh.
- Browser extension + Native Messaging Host cho policy camera/microphone theo
  website origin.
- Installer/service ACL, tamper-evident audit và recovery khi service bị dừng.

V2 cần Windows Driver Kit, chứng thư ký driver và kiểm thử trên máy ảo/snapshot.
Không được giả lập minifilter bằng Python hoặc tự nạp driver chưa ký.

### V2 implementation checkpoint

The workspace now contains the safe foundations for the V2 split:

- `updater/manifest.py` verifies an Ed25519-signed release manifest and the
  downloaded artifact hash. It is verification-only; no network download or
  silent installation is performed.
- `service/ipc_protocol.py` defines a one-time challenge/HMAC envelope with
  client binding. `service/named_pipe.py` now adds explicit ACL, local-only
  transport, peer-token validation, bounded request handling and rate limiting.
- `service/auth_broker.py` and `service/client.py` provide password-proof
  authentication, a 15-minute memory-only service session and short-lived
  resource capabilities without sending plaintext passwords over IPC.
- `service/agent_host.py` and `service/windows_service.py` provide an
  experimental lifecycle boundary. The service is not wired into the GUI EXE
  because the current encrypted data profile is user-scoped; a SYSTEM service
  needs its own protected profile and a deliberate UI-to-service handoff.

The current GUI is not yet a complete thin client; it still talks to its local
controller. Capability-bound service handlers cover the safe policy subset and
reject unsupported mutations. The minifilter, rollback engine, ETW correlation
and browser native-messaging components remain deferred until their
signed/native implementation and test environment are available.

## Advanced — Endpoint Security Platform

Phạm vi mục tiêu: khoảng 150–200 đầu mục theo nhiều mức độ, không phải 700 mục
trong tài liệu tham khảo.

- Bộ cảm biến endpoint: process, registry, scheduled task, service, script,
  credential access indicator, USB và network connection.
- Rule engine theo attack chain, severity, confidence và allowlist có hạn.
- Chế độ isolate endpoint, block hash/path/signer, và rollback theo phiên.
- Phân tích offline; không tải file người dùng lên máy chủ nếu chưa có lựa chọn
  minh bạch và xác nhận riêng.
- Ký code, SBOM, reproducible build, kiểm tra dependency và cập nhật có chữ ký.
- Fuzzing parser, property-based tests, threat-model review và penetration test.

Các nhóm như SQL Injection, XSS, Kubernetes, Cloud, CI/CD, Mobile và AI/LLM
không biến thành tính năng bảo vệ trực tiếp chỉ bằng cách thêm vào FileSentry;
chúng cần sản phẩm hoặc agent chuyên biệt ở lớp tương ứng.
