# FileSentry — Hướng dẫn sử dụng

## 1. Cài đặt

Yêu cầu Windows 10/11 và Python 3.11 trở lên.

```powershell
cd D:\prj-my\FileSentry
python -m pip install -r requirements.txt
python main.py
```

Trong bản đóng gói, chạy `FileSentry.exe` thay cho `python main.py`.

Bản đóng gói được thiết kế chạy với `requireAdministrator` để các thao tác policy Windows có quyền thực thi. UAC vẫn do Windows kiểm soát; FileSentry không bypass hoặc vô hiệu hóa UAC.

## 2. Đăng nhập lần đầu

```text
Tài khoản: admin
Mật khẩu: FileSentry@2026!
```

Sau lần đăng nhập đầu tiên, ứng dụng bắt buộc đặt mật khẩu mới dài ít nhất 12 ký tự,
có chữ hoa, chữ thường, số và ký tự đặc biệt. Không nên dùng lại mật khẩu tạm thời
trong môi trường thật.

## 3. Hướng dẫn tương tác trong ứng dụng

Sau lần đăng nhập đầu tiên, FileSentry tự mở popup **Bắt đầu với FileSentry**. Đây là tour tương tác bám vào control thật trong app:

Popup hiển thị như một bong bóng hướng dẫn nổi; phần còn lại của cửa sổ được làm mờ và chỉ control đang cần thao tác được để sáng rõ.

1. Đọc nội dung và tên control được popup chỉ rõ.
2. Với bước thao tác, control tương ứng trên cửa sổ FileSentry được viền vàng; phải bấm đúng control đó, popup mới tự chuyển bước.
3. Nếu bấm sai vị trí, popup nhắc lại chính xác nút hoặc bảng cần thao tác.
4. Với bước chỉ đọc trạng thái/bảng dữ liệu, quan sát vùng viền vàng rồi bấm **ĐÃ XEM — TIẾP THEO**.
5. Có thể bấm **QUAY LẠI** để xem lại hoặc **ĐÓNG** để kết thúc tour.

Mỗi màn hình có nút **? HƯỚNG DẪN** ở phần tiêu đề. Thanh bên có **HƯỚNG DẪN SỬ DỤNG** để mở hướng dẫn tổng quan bất kỳ lúc nào.

Bạn cũng có thể bấm **chuột phải** ở từng màn hình. Menu chung có **Làm mới màn hình** và **Mở hướng dẫn thao tác**; khi bấm trên bảng dữ liệu, menu sẽ đổi theo mục đang chọn:

- Media Library: xem/mở media, khóa xóa, chống gửi ra ngoài hoặc gỡ bảo vệ.
- Kho mã hóa và Cách ly: khôi phục mục đang chọn.
- Khu vực bảo vệ: xóa phạm vi, mở kho, gỡ quản lý hoặc xử lý Folder Lock.
- Kết nối mạng và Persistence: quét lại bảng dữ liệu.

Các thao tác nhạy cảm từ menu chuột phải vẫn đi qua PasswordGate và audit như nút trên màn hình.

### Chế độ giao diện

Bấm biểu tượng giao diện **◐ / ☼ / ☾** ở góc phải header để mở menu. Bạn có thể chọn:

- **BAN NGÀY**: giao diện nền sáng.
- **BAN ĐÊM**: giao diện nền tối, dịu mắt.
- **THEO WINDOWS**: tự đọc chế độ sáng/tối của Windows và tự cập nhật khi Windows thay đổi.

Lựa chọn này chỉ thay đổi màu sắc giao diện, không thay đổi chính sách bảo vệ, mật khẩu, dữ liệu hay trạng thái khóa tài nguyên. Mục **Cài đặt hệ thống** chỉ hiển thị chế độ hiện tại.

Các bộ hướng dẫn hiện có:

- Bắt đầu với FileSentry.
- Tổng quan.
- Nhật ký hoạt động.
- Khu vực bảo vệ.
- Camera & Microphone Guard.
- Cách ly.
- Cài đặt hệ thống.
- Kết nối mạng.
- Kho mã hóa.
- Ảnh / Video / Âm thanh.
- Startup & Persistence.

## 4. Thêm khu vực bảo vệ

### Luồng bảo vệ thống nhất

Thanh **PROTECTION JOURNEY** luôn xuất hiện ở đầu mỗi màn hình và giữ nguyên thứ tự thao tác:

1. **Tổng quan** — xem trạng thái hiện tại và hành động an toàn tiếp theo.
2. **Phạm vi** — chọn thư mục/khu vực cần giám sát.
3. **Chính sách** — chọn Camera/Microphone, Media Library, Kho mã hóa hoặc Folder Lock.
4. **Theo dõi** — đọc Nhật ký hoạt động, Kết nối mạng và Persistence.
5. **Xử lý** — kiểm tra Cách ly và khôi phục khi đã xác nhận an toàn.

Các màn hình chi tiết chỉ là các điểm trong cùng luồng này. Có thể dùng thanh journey để quay lại bước trước hoặc chuyển sang bước tiếp theo; Access Center là nơi chọn tài nguyên chính sách tập trung. Bản phát hành hiện tại là V1 local defensive console có nền tảng V2; Windows Service thin-client, Minifilter, ETW và browser extension vẫn đang được phát triển.

1. Mở **Khu vực bảo vệ**.
2. Chọn **+ THÊM KHU VỰC**.
3. Chọn thư mục cần giám sát, ví dụ `Documents`, `Desktop` hoặc thư mục dự án.
4. Có thể thêm nhiều thư mục.
5. Dùng **+ THÊM LOẠI TRỪ** để loại trừ cache, temp hoặc thư mục sinh nhiều file.

Chỉ các file nằm trong khu vực bao gồm và không nằm trong khu vực loại trừ mới được xử lý.

### Kho lưu trữ bảo vệ riêng

1. Bấm **+ TẠO KHO LƯU TRỮ**, chọn thư mục gốc và nhập tên thư mục riêng.
2. FileSentry tạo thư mục mới, thêm thư mục đó vào phạm vi `include` và bắt đầu giám sát. Việc thêm include không tự khóa quyền truy cập Explorer.
3. Chọn kho rồi bấm **MỞ THƯ MỤC** để mở bằng Windows Explorer sau khi xác thực. Quyền truy cập thật vẫn do Windows và Folder Lock quyết định.
4. **GỠ QUẢN LÝ (GIỮ THƯ MỤC)** chỉ bỏ nhãn kho riêng trong FileSentry; không xóa thư mục, file hoặc phạm vi giám sát hiện có.

Kho lưu trữ bảo vệ là khu vực được FileSentry giám sát, chưa phải kho mã hóa. Muốn bảo vệ quyền Windows, dùng **Folder Lock**; muốn mã hóa và chống xuất file, dùng **Kho mã hóa**.

### Folder Lock bằng Windows ACL

Trong cùng màn hình **Khu vực bảo vệ**, phần **FOLDER LOCK · WINDOWS ACL** dùng khóa NTFS cho một thư mục cụ thể:

1. Bấm **+ KHÓA THƯ MỤC**, xác thực mật khẩu trong FileSentry và chọn thư mục.
2. FileSentry lưu bản sao DACL gốc vào dữ liệu mã hóa trước khi áp quyền từ chối. Nếu không lưu được bản sao, ACL không được thay đổi.
3. Khi cần dùng lại, chọn thư mục và bấm **MỞ KHÓA MỤC CHỌN**. DACL gốc được khôi phục chính xác.
4. Bấm **KIỂM TRA ACL** để phát hiện thay đổi quyền do bên ngoài FileSentry. Ứng dụng chỉ cảnh báo, không tự ý sửa ACL ngoài quy trình.

Folder Lock là khóa quyền NTFS, không phải mã hóa. Tài khoản Administrator/SYSTEM hoặc công cụ khôi phục quyền của Windows vẫn là ranh giới tin cậy của hệ điều hành.

## 5. Bật, tắt và tạm dừng

- **Tắt bảo vệ**: dừng giám sát nhưng service dữ liệu vẫn còn hoạt động.
- **Bật bảo vệ**: tiếp tục theo dõi theo cấu hình hiện tại.
- **Tạm dừng 15 phút**: dùng khi cần thao tác hàng loạt file.

Các hành động này được ghi vào audit log.

## 6. Xác thực khu vực bảo vệ

Mỗi lần mở **Khu vực bảo vệ**, ứng dụng yêu cầu mật khẩu mới vì đây là khu vực nhạy cảm. Với các thao tác bảo vệ thông thường, sau khi xác thực thành công FileSentry giữ phiên trong bộ nhớ 15 phút; hết thời hạn sẽ yêu cầu nhập lại. Các thao tác rủi ro cao luôn yêu cầu mật khẩu mới:

- Mở Camera/Microphone hoặc mở Windows Privacy Settings.
- Mở, import hoặc restore Vault.
- Gỡ FileSentry và đổi mật khẩu quản trị.
- Khôi phục file trong quarantine.

Các thao tác bật/tắt bảo vệ, tạm dừng và thay đổi phạm vi trong phiên đã mở có thể dùng lại phiên 15 phút.

### Tạm khóa khu vực

**Khóa khu vực** khóa quyền truy cập vào phần quản lý include/exclude của FileSentry trong khoảng thời gian giới hạn. Khi hết thời gian, người dùng phải xác thực lại.

Đây là khóa ở tầng ứng dụng MVP, chưa phải khóa file ở cấp Windows Explorer. Muốn chặn truy cập file thật sự cần filesystem minifilter hoặc driver.

## 7. Cảnh báo ransomware

MVP cảnh báo khi có nhiều event tạo/xóa/đổi tên trong một khoảng thời gian ngắn. Đây là cảnh báo hành vi, không phải kết luận chắc chắn có mã độc.

### Tương quan file và network

FileSentry cũng đối chiếu các thay đổi file đáng chú ý với kết nối Internet bên ngoài trong cùng một cửa sổ thời gian. Khi có đủ bằng chứng, mục **Nhật ký hoạt động** và **Kết nối mạng** hiển thị thẻ **DOUBLE-EXTORTION CORRELATION**:

1. Mở **Nhật ký hoạt động** và đọc số lượng file, kết nối, thời gian và đường dẫn được nêu trong thẻ.
2. Bấm **MỞ BẢNG NETWORK** để kiểm tra process, endpoint và indicator của kết nối.
3. Nếu cần cô lập file, bấm **MỞ CÁCH LY**, chọn file cụ thể và xác nhận trong FileSentry.
4. Ghi nhớ đây là tương quan cần kiểm tra, không phải kết luận máy đã bị xâm nhập. FileSentry không tự gửi telemetry ra ngoài.

Khi nhận cảnh báo:

1. Tạm dừng thao tác file đang chạy.
2. Kiểm tra đường dẫn và ứng dụng liên quan.
3. Không xóa file nghi ngờ ngay.
4. Đưa file vào **Cách ly** nếu cần.
5. Khôi phục chỉ khi đã xác nhận file an toàn.

## 8. Dữ liệu cục bộ

Mặc định dữ liệu nằm trong thư mục `data/` của dự án. Có thể đặt biến môi trường `FILESENTRY_DATA_DIR` để chuyển sang thư mục riêng.

Trong bản chạy thử từ mã nguồn, dữ liệu mặc định nằm trong `data/`. Bản EXE
đóng gói dùng `C:\ProgramData\FileSentry` và áp dụng ACL chỉ cho tài khoản chạy
ứng dụng cùng `SYSTEM`; có thể ghi đè bằng biến môi trường
`FILESENTRY_DATA_DIR` khi triển khai có chủ đích.

Các dữ liệu chính:

- `filesentry.db`: event, alert và audit log.
- `auth.json`: hash mật khẩu, không lưu plaintext.
- `settings.json`: cấu hình include/exclude và trạng thái bảo vệ.
- `quarantine/`: file cách ly và manifest khôi phục.

V1 không tự gửi dữ liệu ra Internet. Nội dung cấu hình, auth, log/audit và file
quarantine được mã hóa bằng AES-GCM; khóa dữ liệu được Windows DPAPI bảo vệ.
Người có quyền Administrator hoặc SYSTEM trên chính máy vẫn thuộc trust boundary
của Windows và có thể can thiệp vào tiến trình đang chạy. Muốn chặn mọi thao tác
từ Explorer cần V2 với Windows Service và Filesystem Minifilter.

## 9. Kiểm tra kết nối mạng

Mở **Kết nối mạng** ở thanh bên để xem socket TCP/UDP cục bộ, process, PID,
địa chỉ local/remote và trạng thái. Network Guard V1:

1. Chỉ đọc bảng kết nối hiện có trên máy.
2. Không quét cổng và không phân giải DNS.
3. Không gửi địa chỉ IP, process path hoặc nhật ký ra Internet.
4. Đánh dấu listener mở trên mọi giao diện, cổng remote đáng chú ý, process từ
   thư mục người dùng và cổng dịch vụ không phổ biến.
5. Không tự động kết luận đây là xâm nhập; cần kiểm tra thêm process, chữ ký số,
   Windows Event Log và phần mềm vừa cài đặt.

V1 không chặn kết nối. Không nên đóng kết nối hệ thống chỉ dựa trên một chỉ báo;
chính sách block/isolate có xác thực và audit sẽ được triển khai ở V2.

## 10. Khôi phục quarantine

Mở **Cách ly**, chọn file và bấm **Khôi phục mục đang chọn**. Ứng dụng không tự ghi đè file đang tồn tại tại đường dẫn gốc.

## 11. Kho mã hóa

Mở **Kho mã hóa** để lưu một bản mã hóa của file:

1. Bấm **ĐƯA FILE VÀO VAULT** và xác thực bằng mật khẩu quản trị.
2. Chọn file cần lưu. File gốc được giữ nguyên; vault tạo bản mã hóa theo chunk.
3. Chọn một mục trong inventory và bấm **KHÔI PHỤC MỤC ĐANG CHỌN**.
4. Chọn đường dẫn đích. FileSentry không ghi đè file đích đã tồn tại.

Vault là kho lưu trữ mã hóa, chưa phải cơ chế khóa mọi thao tác Explorer. Chặn ở cấp hệ thống cần Minifilter/Service của V2.

### Quản lý ảnh, video và âm thanh

Mở **Ảnh / Video / Âm thanh** để quản lý tập trung các file media trên các ổ đĩa cục bộ:

1. Bấm **ĐỒNG BỘ TOÀN BỘ MÁY** để kiểm tra các ổ đĩa cục bộ. File ảnh, video và âm thanh mới sẽ được thêm; file đã thay đổi sẽ được cập nhật; file đã xóa hoặc di chuyển sẽ được đánh dấu **ĐÃ RỜI KHỎI MÁY**. Bạn cũng có thể bấm **+ THÊM FILE MEDIA** để chọn một file.
2. Trong cửa sổ tiến trình, theo dõi số file đã xử lý trên tổng số, phần trăm và thời gian ước tính. Có thể bấm **HỦY ĐỒNG BỘ**; các file chưa kiểm tra sẽ không bị đánh dấu nhầm.
3. Chọn **KHÓA XÓA FILE** để không cho xóa/đổi tên file từ Windows.
4. Chọn **CHỐNG GỬI RA NGOÀI** để đưa file vào Kho riêng mã hóa. Sau khi mã hóa thành công, bản file thường bên ngoài được xóa và chỉ có thể khôi phục qua FileSentry.
5. Chọn **GỠ BẢO VỆ FILE** nếu muốn trả file về quyền thông thường.
6. Chọn một mục rồi bấm **XEM / MỞ MEDIA ĐÃ CHỌN**. Ảnh được xem trong cửa sổ FileSentry; video và âm thanh dạng file ngoài được mở bằng ứng dụng mặc định của Windows. Mục trong Kho riêng không tạo file thường bên ngoài.
7. Bấm **XÓA SẠCH DANH SÁCH (GIỮ FILE)** nếu chỉ muốn làm sạch danh sách trong app. Thao tác này không xóa nội dung ảnh, video, MP3 hoặc file thật; các ACL do FileSentry tạo sẽ được dọn để không để lại khóa mồ côi. Mục Kho riêng được giữ lại.

Chặn gửi ra ngoài tuyệt đối không thể áp dụng cho một file vẫn còn là file thường và mở được từ Explorer hoặc ứng dụng khác. Nếu cần bảo vệ mạnh nhất, hãy dùng **Kho riêng**.

Việc đồng bộ toàn bộ máy là thao tác quét theo yêu cầu. Hãy bấm lại nút đồng bộ sau khi có thay đổi lớn; các mục đã rời máy được giữ lại để bạn còn lịch sử chính sách và biết file nào đã biến mất.

Sau lần đồng bộ đầu tiên, FileSentry tự theo dõi các ổ đĩa đã quét trong lúc ứng dụng đang chạy: file media mới, file được sửa, xóa hoặc đổi tên sẽ được cập nhật vào danh sách. Khi gắn thêm ổ đĩa mới, hãy bấm **ĐỒNG BỘ TOÀN BỘ MÁY** một lần nữa.

## 12. Startup & Persistence

Màn hình này đọc các Run key/RunOnce, Startup folder, Scheduled Task và Service để tạo inventory. Lần quét đầu tạo baseline; thay đổi xuất hiện sau baseline được ghi event và cảnh báo nếu có chỉ báo rủi ro.

FileSentry không tự xóa Registry, Task hoặc Service. Hãy xác minh entry với phần mềm đã cài và dùng công cụ Windows tương ứng khi cần thay đổi.

## 13. Xuất báo cáo sự cố

Trong **Nhật ký hoạt động**, bấm **XUẤT BÁO CÁO SỰ CỐ**:

1. Nhập số giờ cần lấy, từ 1 đến 720.
2. Chọn nơi lưu file `.fsreport`.
3. Báo cáo được mã hóa bằng khóa dữ liệu của FileSentry và có timeline event, alert, audit, hash-chain và posture cục bộ.

Báo cáo là tập hợp chỉ báo cần phân tích, không tự kết luận máy đã bị xâm nhập.

## 14. Sao lưu

Nên sao lưu toàn bộ thư mục dữ liệu sang vị trí khác. Khi triển khai thật, backup cần được mã hóa và kiểm thử khôi phục định kỳ.

## 15. Camera & Microphone Guard

Mở mục **Camera & Microphone** ở thanh bên. Mỗi nút điều khiển đều yêu cầu mật khẩu quản trị.

- **KHÓA**: áp dụng Windows App Privacy Policy và quyền desktop app ở trạng thái từ chối quyền.
- **KHÓA TẠM 15 PHÚT**: từ chối quyền trong 15 phút; hết hạn sẽ chuyển về trạng thái khóa và yêu cầu xác thực để mở lại.
- **MỞ KHÓA**: khôi phục policy trước khi FileSentry khóa thiết bị.
- **MỞ WINDOWS PRIVACY SETTINGS**: mở trang cài đặt quyền tương ứng của Windows.
- **THÊM WEBSITE**: lưu origin như `https://example.com` cho browser extension.

Khóa system-wide có thể yêu cầu chạy bằng Administrator. Khi policy được áp dụng,
browser hoặc ứng dụng đang mở có thể phải khởi động lại. Danh sách website chưa tự
phân biệt URL bên trong browser cho đến khi browser extension/native messaging được triển khai.

## 16. Access Center

Mở **Access Center** để quản lý phiên truy cập camera/microphone:

1. Bấm **MỞ KHÓA 30 PHÚT** và nhập mật khẩu quản trị.
2. FileSentry tạo token chỉ trong bộ nhớ; token không được ghi thành file.
3. Khi hết thời hạn hoặc bấm **KHÓA LẠI**, policy chuyển về Deny và cần xác thực lại.
4. Nếu camera/microphone đang được FileSentry quản lý nhưng bị mở từ Windows Settings hoặc ứng dụng khác, watcher sẽ phát hiện, áp dụng Deny lại và ghi cảnh báo.

Access Center dùng mô hình watch-and-revert có độ trễ polling, không phải cơ chế chặn trước tuyệt đối của Windows. Phiên Vault bảo vệ các thao tác import/restore trong FileSentry; Vault vẫn là kho lưu trữ mã hóa theo file, chưa mount thành ổ đĩa Explorer.

## 17. Gỡ FileSentry

Mở **Cài đặt hệ thống → GỠ FILESENTRY**. Thao tác này yêu cầu:

1. Mật khẩu quản trị.
2. Xác nhận gỡ bản EXE.
3. Lựa chọn có xóa dữ liệu cục bộ hay không.
4. FileSentry tự mở khóa và kiểm tra tất cả Folder Lock. Nếu có mục không khôi phục được DACL, quy trình dừng và không xóa gì.
5. Nhập chính xác `GỠ FILESENTRY`.

Nếu chọn xóa dữ liệu, FileSentry sẽ xóa cấu hình, audit, log, quarantine và khóa
mã hóa trong thư mục dữ liệu dành riêng cho FileSentry. Bản chạy từ mã nguồn không
tự xóa thư mục dự án; chỉ bản EXE đóng gói mới hỗ trợ tự gỡ.

Nếu quên mật khẩu chủ, vào **Cài đặt hệ thống → MỞ KHÓA KHẨN CẤP TẤT CẢ FOLDER LOCK**. Tính năng này yêu cầu quyền Administrator của Windows, có cảnh báo rõ ràng và chỉ khôi phục DACL gốc; nó không giải mã Vault.
