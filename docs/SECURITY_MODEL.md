# FileSentry — Mô hình bảo mật V1

## Tài sản cần bảo vệ

- File và thư mục trong protected roots.
- Mật khẩu quản trị, khóa mã hóa và cấu hình policy.
- Audit log, cảnh báo, manifest và file quarantine.
- Trạng thái camera/microphone và danh sách website policy.

## Ranh giới tin cậy

V1 tin cậy Windows, DPAPI của tài khoản chạy ứng dụng và filesystem của máy.
Local Administrator, SYSTEM, debugger đã được cấp quyền hoặc malware chạy trong
cùng user/session vẫn có thể can thiệp vào một tiến trình user-mode đang chạy.
Đây là giới hạn của hệ điều hành, không thể loại bỏ bằng việc che giấu giao diện.

Vì vậy V1 không tuyên bố chống được malware có quyền Administrator. V2 mới có
thể giảm rủi ro này bằng Service, ACL, Minifilter đã ký và cơ chế tamper response.

## Quy tắc bắt buộc

1. Mật khẩu chỉ dùng để xác thực; không ghi vào log, audit, event hoặc command line.
2. Khóa dữ liệu dùng DPAPI + AES-GCM; mọi ciphertext phải có nonce mới và AAD đúng mục đích.
3. File quarantine phải được mã hóa trước khi xóa bản gốc, có hash kiểm tra khi khôi phục.
4. Đường dẫn nhạy cảm không nhận symbolic link và mã định danh quarantine phải được kiểm tra.
5. File cấu hình ghi nguyên tử; không ghi đè qua symbolic link và không để file tạm tồn tại lâu.
6. Lỗi giải mã, policy hoặc integrity phải fail-closed; không tự động mở quyền.
7. UI không phải là ranh giới bảo mật. V2 phải chuyển thao tác nhạy cảm sang Service.
8. Không có outbound network trong V1; Network Guard chỉ đọc socket cục bộ.
9. Dependency mới phải được xem xét trước khi thêm.

## Gỡ ứng dụng

Uninstall là thao tác destructive nên dùng quy trình hai pha: UI xác thực mật khẩu
và xác nhận văn bản, sau đó mới tạo helper cục bộ chờ process thoát rồi xóa đúng
`FileSentry.exe` và tùy chọn thư mục dữ liệu có tên `FileSentry`. Helper không nhận
đường dẫn từ shell, không xóa thư mục gốc, không tự xóa workspace khi chạy source
và không có kết nối mạng.

## Những điều V1 chưa thể bảo đảm

- Chặn tuyệt đối I/O từ Explorer trước khi thao tác xảy ra.
- Xác định chắc chắn process nào đã gây ra từng file event.
- Bắt buộc website cụ thể trong browser dùng/không dùng camera bằng Windows
  privacy policy thuần túy.
- Khôi phục dữ liệu đã bị mã hóa nếu không có snapshot/backup còn nguyên.
- Bảo vệ khỏi người có quyền Administrator/SYSTEM trên cùng máy.
