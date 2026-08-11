# FileSentry — Thiết kế kỹ thuật V1

## Kiến trúc

MVP hiện chạy một desktop process gồm UI và monitor thread. Kiến trúc mục tiêu khi đóng gói thành sản phẩm là:

```text
Tray/UI process → authenticated IPC → Windows Service/Agent
                                      ├─ scoped monitor
                                      ├─ SQLite writer
                                     ├─ alert engine
                                     └─ quarantine controller
```

Service không nên hiển thị giao diện trực tiếp. Khi chuyển sang Windows Service, cần thêm IPC Named Pipe có ACL và tray process riêng.

## Protected action gate

UI không thực hiện trực tiếp các thao tác nhạy cảm. Lần đầu trong phiên đi qua `PasswordGate`, xác thực với `AuthManager` rồi mở `AuthSession` 15 phút; sau đó controller mới được gọi. Các thao tác rủi ro cao đặt `force_reauth` và bỏ qua session cache:

```text
UI action → PasswordGate/AuthSession → Controller → audit_log + settings
```

Các thao tác được bảo vệ gồm thay đổi include/exclude, bật/tắt giám sát, tạm dừng, tạm khóa khu vực và khôi phục quarantine.

`protected_access_locked` chỉ khóa quyền vào màn hình quản lý phạm vi trong MVP. Nó không thay thế filesystem ACL hoặc kernel minifilter.

## Media Guard

`core/media_guard.py` cung cấp:

- `WindowsPrivacyAdapter`: đọc/ghi Windows App Privacy Policy cho camera và microphone.
- Khi khóa, đồng thời đặt quyền `NonPackaged` của `CapabilityAccessManager` về
  `Deny` để bao phủ browser/desktop app hiện tại.
- `set_media_mode`: `locked`, `temporary`, `unlocked`.
- `allowed_sites`: danh sách origin dành cho browser extension tương lai.
- Backup policy trước khi khóa và khôi phục khi mở khóa/hết hạn.

Khóa policy hệ thống là thao tác đặc quyền và có thể yêu cầu Administrator.
Origin website chỉ là policy data ở MVP; Windows privacy policy không cung cấp URL
của website bên trong browser process. Browser hoặc ứng dụng đang mở có thể cần
khởi động lại để nhận policy mới.

## Access Gateway / Phase 9

`core/access_gateway.py` quản lý grant mở khóa theo tài nguyên. Mỗi grant có token ngẫu nhiên, chỉ giữ digest trong bộ nhớ và tự hết hạn sau thời gian ngắn; không ghi token ra `settings.json` hay log. Controller cấp grant sau `PasswordGate`, sau đó resource adapter mới phục hồi policy.

`core/camera_mic_guard.py` polling policy camera/microphone theo chu kỳ. Với resource đã được người dùng đưa vào chế độ quản lý, trạng thái Allow không có grant hợp lệ sẽ được đổi lại thành Deny và tạo alert kèm thời gian phơi nhiễm quan sát được. Đây là watch-and-revert, không phải pre-hook tuyệt đối của Windows.

Access Center hiển thị trạng thái grant và liên kết vault. Vault V1 không mount thành ổ đĩa; mọi thao tác giải mã vẫn đi qua protected action.

`core/versioning.py` lưu mã hóa `app_version`, `db_schema_version` và `vault_format_version` trong metadata riêng để chuẩn bị migration và rollback. Thay đổi format vault phải có migration tool riêng, không tự giải mã/ghi lại dữ liệu trong lúc khởi động.

## Native enforcement roadmap / V2

Để bắt buộc password khi thao tác file từ Explorer, cần thêm:

```text
native/FileSentryMinifilter.sys
FileSentryService
Named Pipe IPC
FileSentry Browser Extension + Native Messaging Host
```

Python UI hiện đã có policy/audit points nhưng chưa giả lập filesystem blocking.

## Interactive guides

Các hướng dẫn nằm trong `gui/guides.py` dưới dạng registry `GUIDES`. Mỗi màn hình có một `guide_key` và danh sách step gồm tiêu đề + nội dung. `GuidePopup` quản lý:

- chỉ số bước và progress bar;
- nút quay lại, tiếp theo, hoàn tất;
- popup modal nhưng không thay đổi dữ liệu;
- hướng dẫn quick-start tự mở một lần sau đăng nhập đầu tiên;
- nút mở lại hướng dẫn ở sidebar và header từng màn hình.

Khi thêm module mới, cần thêm một guide key tương ứng và gọi `open_guide("module_key")` từ header hoặc nút trợ giúp của module đó.

## Network Guard V1

`core/network_monitor.py` dùng `psutil.net_connections(kind="inet")` để đọc
bảng socket hiện tại trên máy. Không thực hiện reverse DNS, port scan, upload,
hoặc tự động block. Monitor giữ baseline trong bộ nhớ, phát hiện connection mới
đến IP public và tạo chỉ báo giải thích được cho:

- listener trên wildcard address với cổng không nằm trong allowlist dịch vụ phổ biến;
- kết nối ra cổng đáng chú ý;
- process chạy từ thư mục người dùng có kết nối Internet;
- kết nối ESTABLISHED ra cổng không phổ biến.

Network event được mã hóa khi ghi vào DB như các event khác. Một chỉ báo không
phải kết luận máy đã bị xâm nhập; cần đối chiếu Windows Event Log, process path,
chữ ký phần mềm và thời điểm cài đặt. Chặn theo rule hoặc cô lập endpoint thuộc
phạm vi V2 với Windows Service.

## Phạm vi file

`settings.json` có include paths và exclude paths. Đường dẫn được chuẩn hóa bằng `Path.resolve`, không theo dõi symlink/junction ngoài phạm vi mặc định.

## Giám sát

- Ưu tiên `watchdog`/ReadDirectoryChangesW.
- Khi watchdog chưa cài, polling fallback chạy theo chu kỳ 1 giây.
- Event được ghi vào SQLite ở chế độ WAL.
- Hash chỉ thực hiện với file nhỏ hơn giới hạn để tránh làm nghẽn máy.

## Xác thực

Mật khẩu không lưu plaintext. MVP dùng PBKDF2-HMAC-SHA256, salt ngẫu nhiên và 600.000 vòng. Tài khoản seeded phải đổi mật khẩu ở lần đăng nhập đầu.

## Cách ly

File được đổi tên thành ID ngẫu nhiên trong thư mục quarantine. Manifest lưu đường dẫn gốc, hash, lý do và trạng thái khôi phục.

## Kho mã hóa

`core/vault.py` lưu bản mã hóa theo chunk bằng `AppCrypto.encrypt_file`, kèm manifest được mã hóa. Manifest chứa ID ngẫu nhiên, hash SHA-256, kích thước và trạng thái khôi phục. File gốc được giữ nguyên trong V1 để tránh phá hỏng dữ liệu ngoài ý muốn. Khôi phục dùng file tạm, kiểm tra hash và không ghi đè file đích.

Đây là encrypted storage, không phải filesystem enforcement. Khóa Explorer cần Service + Minifilter ở V2.

## Integrity chain và incident report

`core/intrusion_log.py` ghi payload event/alert/audit dưới dạng mã hóa và liên kết mỗi record với hash của record trước. `Database.verify_intrusion_chain()` phát hiện sửa nội dung, đổi thứ tự hoặc chèn record. Cơ chế này không ngăn được việc xóa toàn bộ file bởi tài khoản có quyền trên máy.

`core/incident_report.py` gom timeline cục bộ, kiểm tra chain, network snapshot, persistence snapshot và AV/EDR posture. UI chỉ xuất `.fsreport` mã hóa bằng khóa dữ liệu FileSentry.

## Persistence và AV/EDR posture

`core/persistence_monitor.py` đọc-only Run/RunOnce, Startup folder, Scheduled Task và Windows Service `ImagePath`; baseline được giữ trong bộ nhớ để phát hiện thay đổi. COM/WMI persistence chưa được đưa vào collector hiện tại. `core/system_health.py` gọi lệnh Windows Defender/Security Center cục bộ bằng PowerShell cố định, không nhận lệnh từ dữ liệu Registry và không gọi Internet. Cả hai module chỉ tạo indicator để người dùng xác minh, không tự xóa hoặc tự kết luận malware.

## Giới hạn bảo mật

MVP chỉ phát hiện thay đổi và cảnh báo. Nó không chặn I/O ở kernel-mode, không phải antivirus và không bảo đảm chống lại malware có quyền Administrator.
