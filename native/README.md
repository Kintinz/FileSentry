# FileSentry Native Enforcement Roadmap

Thư mục này dành cho các thành phần cần Windows native code. MVP Python không thể bắt buộc nhập mật khẩu cho mọi thao tác Explorer hoặc biết chính xác website nào trong browser đang dùng camera.

## File I/O

`FileSentryMinifilter.sys` cần:

1. Intercept create/write/delete/rename trong protected roots.
2. Gửi request đã chuẩn hóa tới FileSentry Service.
3. Không hiển thị UI từ kernel; Service/Agent mới xác thực password.
4. Nhận token ngắn hạn theo path/process/expiry.
5. Retry hoặc deny I/O sau khi token được cấp.

## Browser website policy

Mỗi browser cần extension riêng để gửi origin hiện tại tới Native Messaging Host. Windows camera/microphone privacy policy chỉ kiểm soát app/device, không tự kiểm soát URL trong browser process.

## Quy tắc an toàn

- Không gửi password vào kernel driver.
- Không tự động allow tất cả website khi extension không phản hồi.
- Mặc định deny khi policy chưa xác định.
- Driver phải được ký trước khi triển khai Windows 64-bit.
