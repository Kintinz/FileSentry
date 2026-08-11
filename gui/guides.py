"""Interactive, step-by-step in-app guides."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from core.branding import PRODUCT_NAME
from .design_system import COLORS, make_button


GUIDES = {
    "quick_start": {
        "eyebrow": "FIRST RUN",
        "title": "Bắt đầu với FileSentry",
        "steps": [
            ("Chào mừng", "FileSentry giúp bạn theo dõi các thư mục quan trọng, cảnh báo hành vi file bất thường và quản lý file cách ly. Mọi dữ liệu mặc định được lưu cục bộ trên máy."),
            ("Chọn khu vực bảo vệ", "Mở mục Khu vực bảo vệ ở thanh bên. Thêm Documents, Desktop hoặc thư mục dự án. Chỉ những khu vực này mới được FileSentry giám sát."),
            ("Thêm khu vực loại trừ", "Nếu một thư mục tạo nhiều file tạm hoặc cache, hãy thêm vào Khu vực loại trừ để giảm log rác và cảnh báo nhầm."),
            ("Mở lại Tổng quan", "Sau khi cấu hình phạm vi, bấm bước TỔNG QUAN trên Protection Journey để quay về trung tâm điều phối."),
            ("Bật trạng thái bảo vệ", "Trên Tổng quan, chọn Bật / tắt bảo vệ. Bạn sẽ phải nhập lại mật khẩu quản trị trước khi thay đổi trạng thái."),
            ("Theo dõi cảnh báo", "Nhật ký hoạt động hiển thị event mới nhất. Khi có cảnh báo, hãy kiểm tra đường dẫn, dừng thao tác đáng ngờ và chỉ khôi phục file cách ly sau khi đã xác nhận an toàn."),
            ("Bạn đã sẵn sàng", "Bạn có thể mở lại hướng dẫn bất kỳ lúc nào bằng nút HƯỚNG DẪN ở thanh bên hoặc nút ? trên từng màn hình."),
        ],
    },
    "dashboard": {
        "eyebrow": "DASHBOARD GUIDE",
        "title": "Hướng dẫn Tổng quan",
        "steps": [
            ("Trạng thái bảo vệ", "Thẻ trạng thái phía trên cho biết FileSentry đang bảo vệ, đã tắt, tạm dừng hay chưa có khu vực cấu hình."),
            ("Các chỉ số", "Khu vực là số thư mục include, Sự kiện là số event đã ghi, Cảnh báo là alert chưa xử lý và Quarantine là số manifest cách ly."),
            ("Bật / tắt bảo vệ", "Dùng thẻ Bật / tắt bảo vệ để thay đổi trạng thái giám sát. Luôn xác nhận bằng mật khẩu trước khi thay đổi."),
            ("Tạm dừng giám sát", "Tạm dừng dùng khi bạn cần thao tác hàng loạt file hợp lệ. FileSentry sẽ tự hoạt động lại sau thời gian đã chọn."),
            ("Khóa khu vực", "Khóa khu vực yêu cầu xác thực lại trước khi vào màn hình quản lý phạm vi. Đây là khóa ở tầng ứng dụng MVP."),
        ],
    },
    "activity": {
        "eyebrow": "ACTIVITY GUIDE",
        "title": "Hướng dẫn Nhật ký hoạt động",
        "steps": [
            ("Đọc event", "Mỗi dòng thể hiện thời gian, loại event và đường dẫn file trong phạm vi bảo vệ."),
            ("Tìm dấu hiệu bất thường", "Các chuỗi tạo, đổi tên hoặc xóa file nhanh trong thời gian ngắn có thể tạo cảnh báo ransomware."),
            ("Kiểm tra cảnh báo", "Khi nghi ngờ, mở khu vực Cách ly để kiểm tra file liên quan. Không xóa file ngay khi chưa xác nhận."),
            ("Giới hạn của MVP", "Nhật ký ghi nhận thay đổi tốt nhất trong phạm vi đã chọn nhưng chưa khẳng định chắc chắn process gây ra từng event."),
            ("Xuất báo cáo", "Bấm XUẤT BÁO CÁO SỰ CỐ, nhập khoảng thời gian và chọn nơi lưu. Bản .fsreport được mã hóa để phân tích sau."),
            ("Mở báo cáo", "Bấm MỞ BÁO CÁO, xác thực và chọn file .fsreport. FileSentry chỉ hiển thị tóm tắt cục bộ sau khi giải mã thành công."),
        ],
    },
    "network": {
        "eyebrow": "NETWORK POSTURE GUIDE",
        "title": "Hướng dẫn Kết nối mạng",
        "steps": [
            ("Bảng kết nối", "Màn hình hiển thị socket cục bộ, tiến trình, PID, địa chỉ local/remote và trạng thái kết nối."),
            ("Chỉ báo bất thường", "FileSentry đánh dấu listener mở trên mọi giao diện, cổng remote đáng chú ý, tiến trình từ thư mục người dùng và cổng dịch vụ không phổ biến."),
            ("Không kết luận tự động", "Một chỉ báo có thể là phần mềm hợp lệ. Hãy kiểm tra process path, chữ ký phần mềm, thời điểm và nhật ký Windows trước khi xử lý."),
            ("Local-only", "V1 không quét cổng, không phân giải DNS, không gửi IP ra ngoài và không chặn mạng tự động. Chặn theo rule cần Windows Service ở V2."),
        ],
    },
    "vault": {
        "eyebrow": "ENCRYPTED VAULT GUIDE",
        "title": "Hướng dẫn Kho mã hóa",
        "steps": [
            ("Đưa file vào vault", "Bấm ĐƯA FILE VÀO VAULT, nhập mật khẩu và chọn file. File gốc được giữ nguyên; vault tạo một bản mã hóa theo chunk."),
            ("Kiểm tra inventory", "Mỗi mục có ID, thời gian, đường dẫn gốc, kích thước và trạng thái. Nội dung manifest được lưu bảo vệ trong data."),
            ("Khôi phục", "Chọn mục, bấm KHÔI PHỤC và chọn đường dẫn đích. FileSentry không ghi đè file đích đã tồn tại."),
            ("Giới hạn", "Vault là kho lưu trữ mã hóa, không phải khóa thư mục real-time. Muốn chặn thao tác bên ngoài cần V2 với Minifilter."),
        ],
    },
    "media_library": {
        "eyebrow": "MEDIA LIBRARY GUIDE",
        "title": "Hướng dẫn Ảnh / Video / Âm thanh",
        "steps": [
            ("Đồng bộ toàn bộ máy", "Bấm ĐỒNG BỘ TOÀN BỘ MÁY để kiểm tra các ổ đĩa cục bộ. File media mới sẽ được thêm, file đã thay đổi sẽ được cập nhật, còn file đã xóa hoặc di chuyển sẽ được đánh dấu ĐÃ RỜI KHỎI MÁY. Bạn vẫn có thể bấm + THÊM FILE MEDIA để chọn một file cụ thể."),
            ("Theo dõi tiến trình", "Cửa sổ đồng bộ chạy ở nền, hiển thị số file đã xử lý trên tổng số, phần trăm và thời gian ước tính. Bạn có thể bấm HỦY ĐỒNG BỘ; các file chưa kiểm tra sẽ không bị đánh dấu nhầm."),
            ("Khóa xóa", "Chọn file rồi bấm KHÓA XÓA FILE. File vẫn có thể mở, nhưng thao tác xóa hoặc đổi tên sẽ bị từ chối."),
            ("Chống gửi ra ngoài", "Bấm CHỐNG GỬI RA NGOÀI để đưa file vào Kho riêng mã hóa. Khi đó bản file thường bên ngoài sẽ không còn để ứng dụng khác đọc hoặc gửi đi."),
            ("Gỡ bảo vệ", "Chỉ bấm GỠ BẢO VỆ FILE khi bạn chủ động muốn file trở về quyền thông thường của Windows."),
            ("Xem media", "Chọn một mục rồi bấm XEM / MỞ MEDIA ĐÃ CHỌN. Ảnh được xem trong FileSentry có thanh cuộn; video và âm thanh bên ngoài được mở bằng ứng dụng mặc định của Windows. File trong Kho riêng không được tạo bản sao thường bên ngoài."),
            ("Xóa danh sách, giữ file", "Bấm XÓA SẠCH DANH SÁCH (GIỮ FILE) để xóa các mục file ngoài khỏi inventory của FileSentry. Nội dung ảnh, video, MP3 và các file thật không bị xóa; mục Kho riêng được giữ lại để không làm mồ côi dữ liệu mã hóa."),
            ("Giới hạn cần nhớ", "Một file vẫn ở dạng file thường ngoài FileSentry thì không thể bị chặn tuyệt đối việc sao chép hoặc tải lên từ mọi ứng dụng. Muốn bảo vệ mạnh nhất, hãy dùng Kho riêng."),
        ],
    },
    "persistence": {
        "eyebrow": "ENDPOINT POSTURE GUIDE",
        "title": "Hướng dẫn Startup & Persistence",
        "steps": [
            ("Inventory", "Màn hình đọc Run key, RunOnce, Startup folder, Scheduled Task và Service hiện có."),
            ("Baseline", "Lần quét đầu tạo baseline trong bộ nhớ. Những entry xuất hiện sau đó mới được ghi event thay đổi."),
            ("Chỉ báo", "FileSentry đánh dấu command trỏ vào thư mục người dùng; đây là chỉ báo cần kiểm tra, không phải kết luận mã độc."),
            ("Không tự xóa", "FileSentry chỉ giám sát read-only, không tự xóa Registry hoặc Scheduled Task để tránh làm hỏng hệ thống."),
        ],
    },
    "scope": {
        "eyebrow": "PROTECTED SURFACE GUIDE",
        "title": "Hướng dẫn Khu vực bảo vệ",
        "steps": [
            ("Xác thực", "Mỗi lần vào màn hình này, FileSentry yêu cầu mật khẩu quản trị vì đây là phần thay đổi phạm vi bảo vệ."),
            ("Thêm khu vực", "Bấm + THÊM KHU VỰC, chọn một thư mục và xác nhận. Các thư mục con sẽ được giám sát theo cấu hình."),
            ("Loại trừ", "Bấm + THÊM LOẠI TRỪ để bỏ qua cache, temp hoặc thư mục sinh nhiều file. Khu vực loại trừ được ưu tiên hơn include."),
            ("Xóa bảo vệ", "Chọn một dòng rồi bấm XÓA BẢO VỆ MỤC CHỌN. File không bị xóa; chỉ bị loại khỏi phạm vi giám sát."),
            ("Folder Lock ACL", "Trong phần FOLDER LOCK · WINDOWS ACL, bấm + KHÓA THƯ MỤC. FileSentry lưu DACL gốc đã mã hóa trước, rồi mới áp khóa cho tài khoản Windows hiện tại."),
            ("Mở khóa chính xác", "Chọn mục đang khóa rồi bấm MỞ KHÓA MỤC CHỌN. Ứng dụng khôi phục đúng DACL trước khi khóa, không mở rộng quyền tùy ý."),
            ("Mở Tổng quan", "Để xem thao tác khóa khu vực, bấm Tổng quan trên thanh bên. Popup sẽ chuyển sang đúng nút cần dùng trên màn hình đó."),
            ("Khóa khu vực", "Trên Tổng quan, bấm MỞ ở thẻ Khóa khu vực để buộc xác thực lại khi truy cập màn hình Khu vực bảo vệ."),
            ("Quay lại Khu vực bảo vệ", "Sau khi khóa, bấm Khu vực bảo vệ trên thanh bên. Màn hình này sẽ yêu cầu xác thực lại khi chính sách khóa đang còn hiệu lực."),
            ("Kho lưu trữ bảo vệ", "Bấm + TẠO KHO LƯU TRỮ, chọn thư mục gốc và nhập tên kho. FileSentry tạo thư mục riêng, thêm vào phạm vi giám sát và không tự di chuyển hoặc xóa dữ liệu."),
            ("Mở hoặc gỡ quản lý", "Chọn kho rồi bấm MỞ THƯ MỤC để mở bằng Windows Explorer. GỠ QUẢN LÝ chỉ bỏ nhãn riêng trong FileSentry; thư mục, file và phạm vi giám sát vẫn được giữ nguyên."),
        ],
    },
    "quarantine": {
        "eyebrow": "CONTAINMENT GUIDE",
        "title": "Hướng dẫn Cách ly",
        "steps": [
            ("Mục đích", "Quarantine đưa file ra khỏi vị trí làm việc để giảm rủi ro, đồng thời giữ manifest để có thể khôi phục."),
            ("Kiểm tra file", "Xem ID, thời gian, đường dẫn gốc, lý do và trạng thái trước khi quyết định."),
            ("Khôi phục", "Chọn file, bấm KHÔI PHỤC và nhập mật khẩu. Ứng dụng không tự ghi đè nếu đường dẫn gốc đã có file."),
            ("Lưu ý", "Chỉ khôi phục khi bạn xác nhận file an toàn. MVP không tự kết luận file là mã độc thay cho antivirus."),
        ],
    },
    "settings": {
        "eyebrow": "SYSTEM POLICY GUIDE",
        "title": "Hướng dẫn Cài đặt hệ thống",
        "steps": [
            ("Trạng thái", "Kiểm tra trạng thái bảo vệ, quyền truy cập khu vực, ngưỡng cảnh báo và chính sách Internet."),
            ("Chọn giao diện", "Bấm biểu tượng ◐ / ☼ / ☾ ở góc phải header để mở menu, rồi chọn BAN NGÀY, BAN ĐÊM hoặc THEO WINDOWS. Chế độ Theo Windows tự theo thiết lập sáng/tối của Windows và không thay đổi chính sách bảo vệ."),
            ("Phiên xác thực", "Sau lần nhập mật khẩu đầu tiên, phiên xác thực trong bộ nhớ có hiệu lực 15 phút. Thanh SESSION bên trái hiển thị thời gian còn lại."),
            ("Đổi mật khẩu", "Bấm ĐỔI MẬT KHẨU QUẢN TRỊ. Mật khẩu mới phải có ít nhất 12 ký tự, có chữ hoa, chữ thường, số và ký tự đặc biệt."),
            ("Local-only", "Các tính năng gọi ra Internet được thiết kế tắt mặc định trong MVP. Chỉ bật khi bạn hiểu dữ liệu nào sẽ được gửi."),
            ("Giới hạn", "Tắt hoặc tạm dừng chỉ dừng giám sát FileSentry, chưa chặn truy cập file từ Windows Explorer ở cấp kernel."),
            ("Mở khóa khẩn cấp", "Nếu quên mật khẩu chủ, dùng MỞ KHÓA KHẨN CẤP TẤT CẢ FOLDER LOCK trong Cài đặt hệ thống. Tính năng này yêu cầu FileSentry đang chạy bằng quyền Administrator và có xác nhận cảnh báo."),
        ],
    },
    "access": {
        "eyebrow": "ACCESS CENTER GUIDE",
        "title": "Hướng dẫn Access Center",
        "steps": [
            ("Phiên mở khóa", "Mỗi lần bấm MỞ KHÓA, FileSentry yêu cầu mật khẩu và tạo token chỉ ở bộ nhớ, mặc định có thời hạn 30 phút."),
            ("Camera và Microphone", "Khi tài nguyên được quản lý, thay đổi mở ngoài FileSentry sẽ được watcher phát hiện và áp dụng Deny lại trong chu kỳ kiểm tra."),
            ("Khóa lại", "Bấm KHÓA LẠI để thu hồi phiên ngay và áp dụng policy Deny. Hết thời hạn cũng chuyển về trạng thái khóa an toàn."),
            ("Vault", "Vault V1 là kho lưu trữ mã hóa theo file/chunk, không mount như ổ đĩa. Hãy dùng màn hình Kho mã hóa để khôi phục từng file."),
            ("Giới hạn Windows", "Watch-and-revert có độ trễ polling và không phải pre-hook tuyệt đối của Windows; FileSentry hiển thị giới hạn này để tránh hiểu nhầm."),
        ],
    },
    "media": {
        "eyebrow": "MEDIA GUARD GUIDE",
        "title": "Hướng dẫn Camera & Microphone Guard",
        "steps": [
            ("Trạng thái thiết bị", "Màn hình này hiển thị trạng thái camera và microphone. Mỗi thao tác khóa hoặc mở đều yêu cầu mật khẩu quản trị."),
            ("Khóa toàn bộ", "Khóa toàn bộ áp dụng Windows privacy policy ở mức hệ thống và có thể cần quyền Administrator. Ứng dụng đang mở có thể cần khởi động lại."),
            ("Khóa tạm thời", "Khóa tạm thời từ chối camera hoặc microphone đến thời điểm đã chọn. Hết thời hạn, tài nguyên chuyển về trạng thái khóa và cần nhập mật khẩu để mở lại."),
            ("Mở khóa", "Bấm MỞ KHÓA và nhập mật khẩu để tạo phiên mở khóa 30 phút; token không được lưu thành file."),
            ("Website được phép", "Danh sách origin được lưu cho browser extension tương lai. Windows privacy policy không thể tự phân biệt website bên trong một browser process."),
            ("Mở Privacy Settings", "Dùng nút mở Settings để kiểm tra chính sách Windows. Nếu chính sách bị Group Policy khác quản lý, FileSentry có thể không thay đổi được."),
        ],
    },
}


GUIDE_TARGETS = {
    # None means this is an explanation step.  A key means the tour resolves
    # the real widget from FileSentryApp and waits for the user's interaction.
    "quick_start": [None, "workflow_scope", "scope_exclude", "workflow_overview", "dashboard_toggle", "workflow_monitor", "sidebar_help"],
    "dashboard": ["dashboard_status", "dashboard_stats", "dashboard_toggle", "dashboard_pause", "dashboard_lock"],
    "activity": ["activity_tree", "activity_tree", "workflow_recover", None, "activity_export", "activity_open_report"],
    "network": ["network_tree", "network_tree", None, None],
    "vault": ["vault_import", "vault_tree", "vault_restore", None],
    "media_library": ["media_sync", "media_scan_progress", "media_protect", "media_secure", "media_remove", "media_view", "media_clear", None],
    "persistence": ["persistence_tree", "persistence_tree", "persistence_tree", None],
    "scope": [None, "scope_include", "scope_exclude", "scope_remove", "folder_lock_add", "folder_lock_unlock", "workflow_overview", "dashboard_lock", "workflow_scope", "scope_storage", "storage_open"],
    "quarantine": ["quarantine_tree", "quarantine_tree", "quarantine_restore", None],
    "settings": [None, "settings_theme", "sidebar_session", "settings_password", None, None, "settings_emergency"],
    # Unlocking from Access Center opens the detailed Media Guard page.  The
    # tour follows that real navigation, then returns to Access Center before
    # demonstrating the vault entry point.
    "access": ["access_camera_unlock", "media_camera_status", "media_camera_lock", "workflow_policy", "access_vault"],
    "media": ["media_camera_status", "media_camera_lock", "media_camera_temporary", "media_camera_unlock", "media_camera_sites", "media_camera_settings"],
}

# These targets are useful visual anchors but do not represent a click action.
# The guide lets the user confirm them with TIẾP THEO instead of pretending a
# read-only table or status label is a button.
READ_ONLY_TARGETS = {
    "dashboard_status",
    "dashboard_stats",
    "activity_tree",
    "network_tree",
    "vault_tree",
    "persistence_tree",
    "quarantine_tree",
    "sidebar_session",
    "media_camera_status",
    "media_camera_sites",
    "media_scan_progress",
}


class GuidePopup(tk.Toplevel):
    """A non-modal guided tour anchored to the app's real controls.

    Action steps are intentionally click-gated: the popup describes the exact
    control, highlights it in the parent window, and advances only after that
    control receives the click.  Informational steps are marked read-only and
    can be acknowledged with the normal next button.
    """

    def __init__(self, parent, guide_key: str, on_close=None):
        super().__init__(parent)
        self.parent = parent
        self.guide_key = guide_key if guide_key in GUIDES else "quick_start"
        self.guide = GUIDES.get(guide_key, GUIDES["quick_start"])
        self.steps = self.guide["steps"]
        self.target_keys = list(GUIDE_TARGETS.get(self.guide_key, []))
        self.target_keys.extend([None] * max(0, len(self.steps) - len(self.target_keys)))
        self.target_keys = self.target_keys[: len(self.steps)]
        self.index = 0
        self.on_close = on_close
        self._target_bindings = []
        self._root_bind_id = None
        self._previous_root_binding = None
        self._highlighted_target = None
        self._highlight_state = {}
        self._target_refresh_job = None
        self._advance_pending = False
        self._dim_windows = []
        self._spotlight_signature = None
        self.title(f"{PRODUCT_NAME} — {self.guide['title']}")
        self.configure(bg=COLORS["bg"])
        self.geometry("510x370")
        self.minsize(470, 330)
        self.resizable(False, False)
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        root = self.winfo_toplevel()
        self._previous_root_binding = root.bind_all("<ButtonRelease-1>")
        self._root_bind_id = root.bind_all("<ButtonRelease-1>", self._on_any_click, add="+")
        self._render()
        self.after(100, self._position_to_target)
        self._schedule_target_refresh()

    def _build(self):
        # Compact speech-bubble UI. The parent window is dimmed separately;
        # this bubble remains bright and interactive above the spotlight.
        self.overrideredirect(True)
        self.geometry("510x370")
        self.configure(bg=COLORS["amber"])
        try:
            self.attributes("-topmost", True)
        except tk.TclError:
            pass
        shell = tk.Frame(self, bg=COLORS["panel"], highlightbackground=COLORS["amber"], highlightthickness=2)
        shell.pack(fill="both", expand=True, padx=2, pady=2)
        header = tk.Frame(shell, bg=COLORS["panel_alt"])
        header.pack(fill="x")
        tk.Frame(header, bg=COLORS["cyan"], height=4).pack(fill="x")
        tk.Label(header, text="●  HƯỚNG DẪN TRỰC TIẾP", fg=COLORS["cyan"], bg=COLORS["panel_alt"], font=("Segoe UI", 8, "bold")).pack(side="left", padx=15, pady=(13, 3))
        self.counter = tk.Label(header, text="", fg=COLORS["muted"], bg=COLORS["panel_alt"], font=("Segoe UI", 8, "bold"))
        self.counter.pack(side="left", padx=(4, 0), pady=(13, 3))
        tk.Button(header, text="×", command=self.close, bg=COLORS["panel_alt"], fg=COLORS["muted"], activebackground=COLORS["red"], activeforeground=COLORS["text"], relief="flat", bd=0, font=("Segoe UI", 17, "bold"), cursor="hand2").pack(side="right", padx=10, pady=(7, 0))
        self.eyebrow = tk.Label(shell, text="", fg=COLORS["subtle"], bg=COLORS["panel"], font=("Segoe UI", 7, "bold"), anchor="w")
        self.eyebrow.pack(fill="x", padx=18, pady=(12, 0))
        self.title_label = tk.Label(shell, text="", fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 15, "bold"), wraplength=450, justify="left", anchor="w")
        self.title_label.pack(fill="x", padx=18, pady=(2, 7))
        self.progress = tk.Canvas(shell, height=5, bg=COLORS["border_soft"], highlightthickness=0)
        self.progress.pack(fill="x", padx=18, pady=(0, 12))
        self.progress.bind("<Configure>", lambda _event: self._draw_progress())
        self.step_number = tk.Label(shell, text="", fg=COLORS["amber"], bg=COLORS["panel"], font=("Segoe UI", 8, "bold"), anchor="w")
        self.step_number.pack(fill="x", padx=18)
        self.step_title = tk.Label(shell, text="", fg=COLORS["text"], bg=COLORS["panel"], font=("Segoe UI", 16, "bold"), wraplength=450, justify="left", anchor="w")
        self.step_title.pack(fill="x", padx=18, pady=(4, 7))
        card = tk.Frame(shell, bg=COLORS["panel_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        card.pack(fill="both", expand=True, padx=18)
        tk.Frame(card, bg=COLORS["cyan"], height=4).pack(fill="x")
        self.step_body = tk.Label(card, text="", fg=COLORS["muted"], bg=COLORS["panel_soft"], font=("Segoe UI", 9), wraplength=430, justify="left", anchor="nw")
        self.step_body.pack(fill="both", expand=True, padx=15, pady=13)
        self.action_note = tk.Frame(shell, bg=COLORS["info_soft"], highlightbackground=COLORS["border"], highlightthickness=1)
        self.action_note.pack(fill="x", padx=18, pady=(9, 0))
        self.action_label = tk.Label(self.action_note, text="", fg=COLORS["amber"], bg=COLORS["info_soft"], font=("Segoe UI", 8, "bold"), anchor="w", justify="left", wraplength=430)
        self.action_label.pack(fill="x", padx=11, pady=8)
        footer = tk.Frame(shell, bg=COLORS["panel"])
        footer.pack(fill="x", padx=18)
        self.back_button = make_button(footer, "← QUAY LẠI", self.previous, bg=COLORS["panel_alt"], fg=COLORS["muted"], small=True, outline=True)
        self.back_button.pack(side="left", pady=11)
        make_button(footer, "ĐÓNG", self.close, bg=COLORS["panel_alt"], fg=COLORS["muted"], small=True, outline=True).pack(side="right", padx=(5, 0), pady=11)
        self.next_button = make_button(footer, "TIẾP THEO  →", self.next, bg=COLORS["cyan"], fg=COLORS["bg"], small=True)
        self.next_button.pack(side="right", pady=11)
        self.bind("<Left>", lambda _event: self.previous())
        self.bind("<Right>", lambda _event: self.next())
        self.bind("<Escape>", lambda _event: self.close())

    def _current_target_key(self):
        if 0 <= self.index < len(self.target_keys):
            return self.target_keys[self.index]
        return None

    def _resolve_target(self):
        key = self._current_target_key()
        if not key:
            return None
        getter = getattr(self.parent, "get_guide_target", None)
        if not getter:
            return None
        try:
            return getter(key)
        except (AttributeError, tk.TclError):
            return None

    @staticmethod
    def _is_inside(widget, ancestor):
        try:
            widget_path = str(widget)
            ancestor_path = str(ancestor)
            return widget_path == ancestor_path or widget_path.startswith(ancestor_path + ".")
        except (AttributeError, tk.TclError):
            return False

    def _describe_target(self, target):
        try:
            text = target.cget("text")
        except (tk.TclError, TypeError):
            text = ""
        if text:
            return f'“{str(text).strip()}”'
        if target.winfo_class() == "Treeview":
            return "bảng dữ liệu đang được viền vàng"
        return "khu vực đang được viền vàng"

    def _restore_highlight(self):
        target = self._highlighted_target
        if target is None:
            return
        try:
            if target.winfo_exists():
                for option, value in self._highlight_state.items():
                    target.configure(**{option: value})
        except tk.TclError:
            pass
        self._highlighted_target = None
        self._highlight_state = {}

    def _highlight_target(self, target):
        if target is self._highlighted_target:
            return
        self._restore_highlight()
        self._highlighted_target = target
        try:
            if target.winfo_class() == "Treeview":
                style = ttk.Style(self)
                style.configure("Guide.Treeview", bordercolor=COLORS["amber"], borderwidth=3, relief="solid")
                self._highlight_state = {"style": target.cget("style")}
                target.configure(style="Guide.Treeview")
                return
            for option in ("highlightthickness", "highlightbackground", "highlightcolor"):
                try:
                    self._highlight_state[option] = target.cget(option)
                except tk.TclError:
                    pass
            target.configure(highlightthickness=3, highlightbackground=COLORS["amber"], highlightcolor=COLORS["amber"])
        except tk.TclError:
            self._highlighted_target = None
            self._highlight_state = {}

    def _unbind_target(self):
        for widget, sequence, funcid in self._target_bindings:
            try:
                if widget.winfo_exists():
                    widget.unbind(sequence, funcid)
            except tk.TclError:
                pass
        self._target_bindings = []

    def _bind_target(self, target):
        self._unbind_target()
        if target is None or self._current_target_key() in READ_ONLY_TARGETS:
            return
        for sequence in ("<ButtonRelease-1>", "<<TreeviewSelect>>" if target.winfo_class() == "Treeview" else None):
            if not sequence:
                continue
            try:
                funcid = target.bind(sequence, self._target_clicked, add="+")
                self._target_bindings.append((target, sequence, funcid))
            except tk.TclError:
                pass

    def _destroy_dim_windows(self):
        for window in self._dim_windows:
            try:
                window.destroy()
            except tk.TclError:
                pass
        self._dim_windows = []
        self._spotlight_signature = None

    def _dim_click(self, _event=None):
        target = self._resolve_target()
        if target is None:
            return
        try:
            self.action_label.configure(
                text=f"Đây là vùng đang bị làm mờ. Hãy bấm đúng control {self._describe_target(target)} đang sáng.",
                fg=COLORS["red"],
            )
        except tk.TclError:
            pass

    def _create_dim_window(self, x, y, width, height):
        if width <= 2 or height <= 2:
            return
        root = self.parent.winfo_toplevel()
        try:
            window = tk.Toplevel(root)
            window.overrideredirect(True)
            window.configure(bg=COLORS["bg"])
            try:
                window.attributes("-alpha", 0.76)
                window.attributes("-topmost", True)
            except tk.TclError:
                pass
            window.geometry(f"{int(width)}x{int(height)}+{int(x)}+{int(y)}")
            window.bind("<Button-1>", self._dim_click, add="+")
            window.bind("<ButtonRelease-1>", self._dim_click, add="+")
            window.transient(root)
            self._dim_windows.append(window)
        except tk.TclError:
            pass

    def _update_spotlight(self, target):
        """Dim the app while leaving only the current target uncovered."""
        try:
            root = self.parent.winfo_toplevel()
            root.update_idletasks()
            root_x, root_y = root.winfo_rootx(), root.winfo_rooty()
            root_w, root_h = max(root.winfo_width(), 1), max(root.winfo_height(), 1)
            host_x, host_y = root_x, root_y
            host_right, host_bottom = root_x + root_w, root_y + root_h
            hole = None
            if target is not None:
                target.update_idletasks()
                tx, ty = target.winfo_rootx() - 8, target.winfo_rooty() - 8
                tright = target.winfo_rootx() + max(target.winfo_width(), 1) + 8
                tbottom = target.winfo_rooty() + max(target.winfo_height(), 1) + 8
                # Include a detached app dialog in the dimmed bounds while
                # keeping the spotlight hole around its actual widget.
                host_x = min(host_x, tx)
                host_y = min(host_y, ty)
                host_right = max(host_right, tright)
                host_bottom = max(host_bottom, tbottom)
                hole = (max(host_x, tx), max(host_y, ty), min(host_right, tright), min(host_bottom, tbottom))
            signature = (str(target) if target is not None else None, host_x, host_y, host_right, host_bottom, hole)
            if signature == self._spotlight_signature and self._dim_windows:
                return
            self._destroy_dim_windows()
            self._spotlight_signature = signature
            if hole is None:
                self._create_dim_window(host_x, host_y, host_right - host_x, host_bottom - host_y)
            else:
                hx, hy, hright, hbottom = hole
                # Four panels leave a true transparent cut-out over the
                # target; no click-through trick or system policy is needed.
                self._create_dim_window(host_x, host_y, host_right - host_x, hy - host_y)
                self._create_dim_window(host_x, hbottom, host_right - host_x, host_bottom - hbottom)
                self._create_dim_window(host_x, hy, hx - host_x, hbottom - hy)
                self._create_dim_window(hright, hy, host_right - hright, hbottom - hy)
            self.lift()
        except tk.TclError:
            pass

    def _on_any_click(self, event):
        if self._is_inside(event.widget, self):
            return
        target = self._resolve_target()
        if target is None or self._current_target_key() in READ_ONLY_TARGETS:
            return
        if not self._is_inside(event.widget, target):
            try:
                self.action_label.configure(text=f"Hãy bấm đúng control {self._describe_target(target)} trên cửa sổ FileSentry.", fg=COLORS["red"])
            except tk.TclError:
                pass

    def _target_clicked(self, _event=None):
        if self._advance_pending:
            return
        self._advance_pending = True
        try:
            self.action_label.configure(text="Đã nhận đúng thao tác. Đang chuyển sang bước tiếp theo…", fg=COLORS["green"])
        except tk.TclError:
            pass
        self.after(140, self._advance_from_target)

    def _advance_from_target(self):
        self._advance_pending = False
        if not self.winfo_exists():
            return
        if self.index < len(self.steps) - 1:
            self.index += 1
            self._render()
        else:
            self.close()

    def _refresh_target(self):
        self._target_refresh_job = None
        if not self.winfo_exists():
            return
        target = self._resolve_target()
        if target is not None:
            self._highlight_target(target)
            self._bind_target(target)
            self._update_spotlight(target)
            if self._current_target_key() in READ_ONLY_TARGETS:
                self.action_label.configure(text=f"Quan sát {self._describe_target(target)}, sau đó bấm TIẾP THEO.", fg=COLORS["cyan"])
                self.next_button.configure(state="normal", text="ĐÃ XEM — TIẾP THEO  →")
            else:
                self.action_label.configure(text=f"BẤM ĐÚNG CONTROL: {self._describe_target(target)}. Popup chỉ chuyển bước sau thao tác này.", fg=COLORS["amber"])
                self.next_button.configure(state="disabled", text="BẤM ĐIỂM ĐƯỢC CHỈ DẪN")
            self._position_to_target()
        elif self._current_target_key():
            self._restore_highlight()
            self._unbind_target()
            self._update_spotlight(None)
            self._position_to_target()
            self.action_label.configure(text="Đang chờ màn hình hoặc hộp thoại của bước này mở… hoàn thành thao tác hiện tại trên FileSentry.", fg=COLORS["amber"])
            self.next_button.configure(state="disabled", text="ĐANG CHỜ CONTROL…")
        else:
            self._restore_highlight()
            self._unbind_target()
            self._update_spotlight(None)
            self._position_to_target()
            self.action_label.configure(text="BƯỚC GIẢI THÍCH: đọc nội dung rồi bấm TIẾP THEO để tiếp tục.", fg=COLORS["cyan"])
            self.next_button.configure(state="normal")
        self._target_refresh_job = self.after(250, self._refresh_target)

    def _schedule_target_refresh(self):
        if self._target_refresh_job is None and self.winfo_exists():
            self._target_refresh_job = self.after(0, self._refresh_target)

    def _position_to_target(self):
        target = self._resolve_target()
        try:
            if target is None:
                root = self.parent.winfo_toplevel()
                root.update_idletasks()
                self.update_idletasks()
                width = self.winfo_width() or 510
                height = self.winfo_height() or 370
                x = root.winfo_rootx() + max(0, (root.winfo_width() - width) // 2)
                y = root.winfo_rooty() + max(0, (root.winfo_height() - height) // 2)
                self.geometry(f"{width}x{height}+{x}+{y}")
                self.lift()
                return
            target.update_idletasks()
            self.update_idletasks()
            width = self.winfo_width() or 650
            height = self.winfo_height() or 560
            target_x = target.winfo_rootx()
            target_y = target.winfo_rooty()
            target_w = max(target.winfo_width(), 1)
            target_h = max(target.winfo_height(), 1)
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            x = target_x + target_w + 16
            if x + width > screen_w - 12:
                x = target_x - width - 16
            y = max(12, min(target_y, screen_h - height - 48))
            x = max(12, min(x, screen_w - width - 12))
            self.geometry(f"{width}x{height}+{x}+{y}")
            self.lift()
        except tk.TclError:
            pass

    def _draw_progress(self):
        width = max(self.progress.winfo_width(), 1)
        self.progress.delete("all")
        self.progress.create_rectangle(0, 0, width, 5, fill=COLORS["border_soft"], outline="")
        self.progress.create_rectangle(0, 0, width * ((self.index + 1) / len(self.steps)), 5, fill=COLORS["cyan"], outline="")

    def _render(self):
        title, body = self.steps[self.index]
        self.eyebrow.configure(text=self.guide["eyebrow"])
        self.title_label.configure(text=self.guide["title"])
        self.counter.configure(text=f"{self.index + 1} / {len(self.steps)}")
        self.step_number.configure(text=f"BƯỚC {self.index + 1:02d}")
        self.step_title.configure(text=title)
        self.step_body.configure(text=body)
        self.back_button.configure(state="normal" if self.index else "disabled")
        self.next_button.configure(text="HOÀN TẤT  ✓" if self.index == len(self.steps) - 1 else "TIẾP THEO  →")
        self._draw_progress()
        self._schedule_target_refresh()

    def next(self):
        if self._current_target_key() and self._current_target_key() not in READ_ONLY_TARGETS:
            target = self._resolve_target()
            if target is not None:
                self.action_label.configure(text=f"Hãy bấm đúng control {self._describe_target(target)} trên app trước khi chuyển bước.", fg=COLORS["red"])
            return
        if self.index >= len(self.steps) - 1:
            self.close()
            return
        self.index += 1
        self._render()

    def previous(self):
        if self.index:
            self.index -= 1
            self._render()

    def close(self):
        if self._target_refresh_job:
            try:
                self.after_cancel(self._target_refresh_job)
            except tk.TclError:
                pass
            self._target_refresh_job = None
        self._unbind_target()
        self._restore_highlight()
        self._destroy_dim_windows()
        if self._root_bind_id:
            try:
                root = self.winfo_toplevel()
                root.unbind_all("<ButtonRelease-1>")
                if self._previous_root_binding:
                    root.bind_all("<ButtonRelease-1>", self._previous_root_binding)
            except tk.TclError:
                pass
            self._root_bind_id = None
            self._previous_root_binding = None
        if self.on_close:
            self.on_close()
        self.destroy()
