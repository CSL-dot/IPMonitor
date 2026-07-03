# -*- coding = utf-8 -*-
# @Time :2026/3/16 8:55
# @Author:CSL (Ultimate Interactive Dashboard with ICO Support)
# @File :bds-monitor-final.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import time
import logging
import os
import sys
import socket
import subprocess
import platform
from datetime import datetime, timedelta, date
from typing import Dict, List, Tuple

# ===================== 核心静态配置 =====================
DEFAULT_CONFIG_FILE = "ip.config"
TIMEOUT = 5  # 检测超时时间（秒）
CHECK_INTERVAL = 10  # 检测间隔（秒）
LOG_FOLDER = "ip_monitor_logs"
PROTOCOLS = ["http://", "https://"]
MAX_THREADS = 50  # 线程池最大线程数

# 初始化日志目录
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# 配置基础日志输出
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
    datefmt='%H:%M:%S',
    force=True
)


# ===================== 辅助工具函数 =====================
def get_resource_path(relative_path: str) -> str:
    """获取资源的绝对路径 (兼容 PyInstaller 打包后的临时释放目录与日常开发环境)"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def format_duration(seconds: float) -> str:
    """格式化秒级时长为可读的汉字表示"""
    if seconds < 60:
        return f"{int(seconds)}秒"
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}分{int(seconds % 60)}秒"
    hours = minutes / 60
    return f"{int(hours)}时{int(minutes % 60)}分"


# ===================== 底层多维度网络探测工具方法 =====================
def ping_check(ip: str, timeout_ms: int = 1000) -> Tuple[bool, str]:
    """跨平台多线程安全 Ping (ICMP) 检测"""
    clean_ip = ip.split(":")[0].replace("http://", "").replace("https://", "").strip()

    is_win = platform.system().lower() == "windows"
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), clean_ip] if is_win else \
        ["ping", "-c", "1", "-W", str(int(timeout_ms / 1000)), clean_ip]

    # 动态参数字典，避免在 Linux/macOS 上传入 Windows 专属参数引发异常
    run_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": (timeout_ms / 1000) + 1
    }

    # 核心修复：如果是 Windows 系统，注入 0x08000000 (CREATE_NO_WINDOW) 标志，强制静默执行
    if is_win:
        run_kwargs["creationflags"] = 0x08000000

    try:
        res = subprocess.run(cmd, **run_kwargs)
        if res.returncode == 0:
            return True, "Ping 成功"
        return False, "Ping 失败 (超时/不可达)"
    except subprocess.TimeoutExpired:
        return False, "Ping 超时"
    except Exception as e:
        return False, f"Ping 异常: {str(e)[:30]}"


def tcp_check(ip: str, default_port: int = 80, timeout: float = 3.0) -> Tuple[bool, str]:
    """针对 GNSS 数据流端口的快速 TCP 连接探测"""
    clean_ip = ip.replace("http://", "").replace("https://", "").strip()
    if ":" in clean_ip:
        parts = clean_ip.split(":")
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = default_port
    else:
        host = clean_ip
        port = default_port

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"TCP 端口 {port} 握手成功"
    except socket.timeout:
        return False, f"TCP 端口 {port} 连接超时"
    except Exception as e:
        return False, f"TCP 端口 {port} 连通失败: {str(e)[:25]}"


def http_check(session: requests.Session, ip: str, timeout: float = 3.0) -> Tuple[bool, str]:
    """智能 HTTP 检测 (支持连接复用，屏蔽SSL警告)"""
    url = ip if (ip.startswith("http://") or ip.startswith("https://")) else f"http://{ip}"

    # 1. 尝试 HEAD 请求
    try:
        response = session.head(url, timeout=timeout, allow_redirects=True, verify=False,
                                headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code < 500:
            return True, f"HTTP HEAD {response.status_code}"
    except Exception:
        pass

    # 2. 备用 GET 请求
    try:
        response = session.get(url, timeout=timeout, allow_redirects=True, verify=False,
                               headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code < 500:
            return True, f"HTTP GET {response.status_code}"
        return False, f"HTTP 状态码异常: {response.status_code}"
    except requests.exceptions.Timeout:
        return False, "HTTP 超时"
    except requests.exceptions.ConnectionError:
        return False, "HTTP 无法建连"
    except Exception as e:
        return False, f"HTTP 异常: {str(e)[:30]}"


def auto_check(session: requests.Session, ip: str) -> Tuple[bool, str]:
    """智能链式自适应自检 (HTTP -> TCP:80 -> Ping)"""
    ok, msg = http_check(session, ip, timeout=2.0)
    if ok:
        return True, msg

    ok, msg = tcp_check(ip, default_port=80, timeout=2.0)
    if ok:
        return True, msg

    ok, msg = ping_check(ip, timeout_ms=1000)
    if ok:
        return True, msg

    return False, "自检全败 (HTTP/TCP/Ping 均失败)"


# ===================== 动态自适应时间轴标尺组件 =====================
class TimelineHeaderAxis(tk.Canvas):
    """自适应宽度的滑动时间轴刻度尺组件"""

    def __init__(self, parent, height=30, **kwargs):
        bg_color = ttk.Style().lookup("TFrame", "background") or "#F0F0F0"
        super().__init__(parent, height=height, bg=bg_color, highlightthickness=0, **kwargs)
        self.height = height
        self.width = 100
        self.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        self.width = event.width
        self.update_axis()

    def update_axis(self):
        self.delete("all")
        now = datetime.now()

        # 1. 绘制横线：Y坐标从 20 修改为 24
        self.create_line(0, 24, self.width, 24, fill="#7F8C8D", width=1)

        ticks = [
            (0.0, -24),
            (0.25, -18),
            (0.50, -12),
            (0.75, -6),
            (1.0, 0)
        ]

        for ratio, hours_offset in ticks:
            x = ratio * self.width

            if ratio == 0.0:
                anchor = tk.W
            elif ratio == 1.0:
                anchor = tk.E
            else:
                anchor = tk.CENTER

            # 2. 绘制主刻度短线：Y坐标范围从 15~20 修改为 19~24
            self.create_line(x, 19, x, 24, fill="#7F8C8D", width=1)

            target_time = now + timedelta(hours=hours_offset)

            if hours_offset == 0:
                time_str = f"现在 ({target_time.strftime('%H:%M')})"
            else:
                day_prefix = "昨日" if target_time.date() < now.date() else "今日"
                time_str = f"{day_prefix} {target_time.strftime('%H:%M')}"

            # 3. 绘制文字：Y坐标由 5 修改为 9
            self.create_text(x, 9, text=time_str, fill="#5A626A", font=("Times New Roman", 10), anchor=anchor)


# ===================== 高精度自适应滚动时间线组件 =====================
class PrecisionTimelineBar(tk.Canvas):
    """
    24小时高精度自适应进度条。
    采用“对象复用”渲染，并支持鼠标悬停时动态计算该区域状态下的“连续持续时长”。
    """

    def __init__(self, parent, height=24, **kwargs):
        super().__init__(parent, height=height, bg="#E2E8F0", highlightthickness=0, **kwargs)
        self.height = height
        self.width = 100

        self.offline_events: List[List[float]] = []
        self.first_monitor_ts: float = None

        # 状态起算时间戳（仅在状态真正发生切换时更新）
        self.last_status = None
        self.last_status_time: float = None

        # --- 图元对象池缓存 ---
        self.bg_rect_id = None
        self.green_rect_id = None
        self.red_rect_ids: List[int] = []

        # --- 悬停提示对象缓存 ---
        self.hover_line_id = None
        self.hover_rect_id = None
        self.hover_text_id = None

        self.bind("<Configure>", self._on_resize)
        self.bind("<Motion>", self._on_hover)
        self.bind("<Leave>", self._on_leave)

    def _on_resize(self, event):
        """画布尺寸变动时触发自动重绘"""
        self.width = event.width
        self.redraw()

    def _on_hover(self, event):
        """鼠标划过进度条时，基于状态跃迁记录，精确计算悬浮处的“持续运行时长”"""
        if self.last_status is None or self.width <= 0:
            return

        x = max(0, min(event.x, self.width))
        now = time.time()
        start_time = now - 86400  # 24小时起点

        # 像素映射计算对应历史时间戳
        target_ts = start_time + (x / self.width) * 86400

        state_str = "暂无数据"
        text_color = "#7F8C8D"
        duration_desc = ""

        # 智能诊断及阶段时长测算
        if self.first_monitor_ts is not None and target_ts >= self.first_monitor_ts:
            state_str = "运行正常"
            text_color = "#27AE60"

            is_fault = False
            for start_ts, end_ts in self.offline_events:
                if start_ts <= target_ts <= end_ts:
                    state_str = "故障断开"
                    text_color = "#C0392B"
                    is_fault = True
                    # 测算该异常历史周期的持续时长
                    duration_desc = f" (持续 {format_duration(end_ts - start_ts)})"
                    break

            if not is_fault:
                # 测算当前在线阶段至鼠标指向处的累积运行时间
                online_period_start = self.first_monitor_ts
                for start_ts, end_ts in self.offline_events:
                    if end_ts < target_ts:
                        online_period_start = max(online_period_start, end_ts)
                duration_desc = f" (已运行 {format_duration(target_ts - online_period_start)})"

        # 格式化悬浮气泡内容
        target_dt = datetime.fromtimestamp(target_ts)
        now_dt = datetime.fromtimestamp(now)
        day_prefix = "昨日" if target_dt.date() < now_dt.date() else "今日"
        time_formatted = f"{day_prefix} {target_dt.strftime('%H:%M:%S')}"
        full_text = f"{time_formatted} [{state_str}]{duration_desc}"

        # 1. 绘制或更新垂直虚线
        if self.hover_line_id is None:
            self.hover_line_id = self.create_line(x, 0, x, self.height, fill="#2C3E50", dash=(3, 3), width=1)
        else:
            self.coords(self.hover_line_id, x, 0, x, self.height)
            self.tag_raise(self.hover_line_id)

        # 2. 绘制或更新提示文字
        if x > self.width - 190:  # 考虑时长字数，防溢出宽度自适应微调
            text_anchor = tk.E
            tx = x - 10
        else:
            text_anchor = tk.W
            tx = x + 10

        ty = self.height / 2

        if self.hover_text_id is None:
            self.hover_text_id = self.create_text(
                tx, ty, text=full_text, fill=text_color,
                font=("Times New Roman", 8, "bold"), anchor=text_anchor
            )
        else:
            self.itemconfig(self.hover_text_id, text=full_text, fill=text_color, anchor=text_anchor)
            self.coords(self.hover_text_id, tx, ty)
            self.tag_raise(self.hover_text_id)

        # 3. 动态绘制或更新文本背后的遮罩框
        bbox = self.bbox(self.hover_text_id)
        if bbox:
            x1, y1, x2, y2 = bbox
            x1 -= 4
            y1 -= 2
            x2 += 4
            y2 += 2

            if self.hover_rect_id is None:
                self.hover_rect_id = self.create_rectangle(x1, y1, x2, y2, fill="#FFFFFF", outline="#BDC3C7", width=1)
            else:
                self.coords(self.hover_rect_id, x1, y1, x2, y2)
                self.tag_raise(self.hover_rect_id)

            self.tag_raise(self.hover_text_id)

    def _on_leave(self, event):
        """鼠标离开时即时销毁提示组件"""
        if self.hover_line_id is not None:
            self.delete(self.hover_line_id)
            self.hover_line_id = None
        if self.hover_rect_id is not None:
            self.delete(self.hover_rect_id)
            self.hover_rect_id = None
        if self.hover_text_id is not None:
            self.delete(self.hover_text_id)
            self.hover_text_id = None

    def record_status(self, is_online: bool):
        """仅在状态真正发生切换时记录重置 last_status_time"""
        now = time.time()

        if self.first_monitor_ts is None:
            self.first_monitor_ts = now

        if self.last_status is None:
            self.last_status = is_online
            self.last_status_time = now  # 首次初始化跃迁时间
            if not is_online:
                self.offline_events.append([now, now])
        else:
            if not is_online:
                if self.last_status is True:
                    # 发生变迁（正常 -> 故障）：此时才更新 last_status_time
                    self.offline_events.append([now, now])
                    self.last_status_time = now
                else:
                    # 持续故障（状态未变，不修改 last_status_time）
                    if self.offline_events:
                        self.offline_events[-1][1] = now
                    else:
                        self.offline_events.append([now, now])
            else:
                if self.last_status is False:
                    # 发生变迁（故障 -> 正常）：此时才更新 last_status_time
                    if self.offline_events:
                        self.offline_events[-1][1] = now
                    self.last_status_time = now

            self.last_status = is_online

        # 裁剪过期事件
        cutoff = now - 86400
        self.offline_events = [ev for ev in self.offline_events if ev[1] > cutoff]
        for ev in self.offline_events:
            if ev[0] < cutoff:
                ev[0] = cutoff

        self.redraw()

    def redraw(self):
        """采用 coords 增量重定位，避免重绘开销"""
        now = time.time()
        start_time = now - 86400  # 24小时起点

        # 1. 灰色背景
        if self.bg_rect_id is None:
            self.bg_rect_id = self.create_rectangle(0, 0, self.width, self.height, fill="#E2E8F0", outline="")
        else:
            self.coords(self.bg_rect_id, 0, 0, self.width, self.height)

        # 2. 正常绿色运行区
        green_start = None
        if self.first_monitor_ts is not None:
            green_start = max(start_time, self.first_monitor_ts)

        if self.last_status is not None and green_start is not None and green_start < now:
            x_green_start = self.width * (green_start - start_time) / 86400
            x_green_end = self.width

            if self.green_rect_id is None:
                self.green_rect_id = self.create_rectangle(x_green_start, 0, x_green_end, self.height, fill="#2ECC71",
                                                           outline="")
            else:
                self.coords(self.green_rect_id, x_green_start, 0, x_green_end, self.height)
        else:
            if self.green_rect_id is not None:
                self.coords(self.green_rect_id, 0, 0, 0, 0)

        # 3. 红色故障段
        num_events = len(self.offline_events)

        while len(self.red_rect_ids) < num_events:
            rect_id = self.create_rectangle(0, 0, 0, 0, fill="#E74C3C", outline="")
            self.red_rect_ids.append(rect_id)

        for i, (start_ts, end_ts) in enumerate(self.offline_events):
            x1 = self.width * (start_ts - start_time) / 86400
            x2 = self.width * (end_ts - start_time) / 86400

            if x2 - x1 < 2.0:
                x2 = x1 + 2.0

            self.coords(self.red_rect_ids[i], x1, 0, x2, self.height)

        for i in range(num_events, len(self.red_rect_ids)):
            self.coords(self.red_rect_ids[i], 0, 0, 0, 0)


# ===================== 自定义滚动框架 =====================
class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas_window = self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.bind('<Configure>', self._on_canvas_configure)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.canvas.bind("<Enter>", lambda _: self.canvas.bind_all("<MouseWheel>", self._on_mousewheel))
        self.canvas.bind("<Leave>", lambda _: self.canvas.unbind_all("<MouseWheel>"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_window, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")


# ===================== 主应用程序 =====================
class IPMonitorApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("GNSS接收机IP监控")
        self.root.geometry("1000x620")
        self.root.minsize(800, 400)

        # ------------------ 状态变量 ------------------
        self.is_running = False
        self.ip_list: List[Tuple[str, str, str]] = []  # (站点名, IP, 检测策略)

        # 核心检测状态记录
        self.station_current_status: Dict[str, bool] = {}
        self.station_first_status_time: Dict[str, Tuple[bool, str]] = {}

        # 进度条控件缓存
        self.timeline_bars: Dict[str, PrecisionTimelineBar] = {}

        # 日期控制
        self.today = date.today()
        self.yesterday = self.today - timedelta(days=1)

        # 线程与通信
        self.update_queue = queue.Queue(maxsize=200)
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_THREADS)

        # 核心改进：采用 thread-local 保证连接池（Keep-Alive）的线程隔离与线程安全
        self.thread_local = threading.local()

        # 心跳记录：维护当前整点，每小时写入一次日志作为“运行中”的断点凭证
        self.last_heartbeat_hour: int = None

        # ------------------ UI构建与调度 ------------------
        self._set_style()
        self._create_widgets()
        self._process_queue()

        # 启动时间轴刷新和自适应重绘（每30s）
        self._start_time_axis_loop()
        self._schedule_date_check()

        self._load_config(DEFAULT_CONFIG_FILE)

    def _set_style(self):
        """中英文双字体统一化配置"""
        style = ttk.Style()
        self.root.option_add("*Font", "SimSun 10")

        style.configure(".", font=("SimSun", 10))
        style.configure("TLabelframe.Label", font=("SimSun", 10, "bold"))
        style.configure("TEntry", font=("Times New Roman", 10))

    def _create_widgets(self):
        """构建自适应宽屏监控看板"""
        # 顶部操作面板
        top_frame = ttk.Frame(self.root, padding="10")
        top_frame.pack(fill=tk.X, anchor=tk.N)

        ttk.Label(top_frame, text="IP配置文件:", font=("SimSun", 10)).pack(side=tk.LEFT, padx=2)
        self.file_var = tk.StringVar(value=DEFAULT_CONFIG_FILE)
        self.file_entry = ttk.Entry(top_frame, textvariable=self.file_var, width=30)
        self.file_entry.pack(side=tk.LEFT, padx=2, fill=tk.X)

        ttk.Button(top_frame, text="选择", command=self._select_file, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Button(top_frame, text="加载", command=self._load_selected_file, width=6).pack(side=tk.LEFT, padx=2)

        self.start_btn = ttk.Button(top_frame, text="开始监控", command=self._start_monitor, width=10)
        self.start_btn.pack(side=tk.LEFT, padx=8)
        self.stop_btn = ttk.Button(top_frame, text="停止监控", command=self._stop_monitor, state=tk.DISABLED, width=10)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        # 监控列表容器
        station_col = ttk.LabelFrame(self.root, text=" 节点状态监控面板 ", padding="10")
        station_col.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # 顶部指标摘要 + 图例栏
        legend_frame = ttk.Frame(station_col)
        legend_frame.pack(fill=tk.X, pady=5, padx=5)

        # 混合区采用 Times New Roman 保证数字和符号的美观
        self.summary_label = ttk.Label(legend_frame, text="节点总数: -- | 在线: -- | 故障: --",
                                       font=("Times New Roman", 10, "bold"), foreground="#1A73E8")
        self.summary_label.pack(side=tk.LEFT, padx=5)

        ttk.Label(legend_frame, text=" 未就绪/暂无数据 ■", foreground="#7F8C8D", font=("SimSun", 9)).pack(side=tk.RIGHT,
                                                                                                   padx=5)
        ttk.Label(legend_frame, text=" 异常/瞬断 ■", foreground="#E74C3C", font=("SimHei", 9)).pack(side=tk.RIGHT, padx=5)
        ttk.Label(legend_frame, text=" 正常运行 ■", foreground="#2ECC71", font=("SimSun", 9)).pack(side=tk.RIGHT, padx=5)
        ttk.Label(legend_frame, text="图例:", font=("SimSun", 9, "bold")).pack(side=tk.RIGHT, padx=5)

        # 表格头部线，集成自适应共享刻度时间轴
        table_header = ttk.Frame(station_col, padding=2)
        table_header.pack(fill=tk.X, padx=5)

        # 站点名称列头占位 (宋体，宽度10像素水平左对齐)
        ttk.Label(table_header, text="站点名称", width=10, font=("SimSun", 10, "bold"), anchor=tk.W).pack(side=tk.LEFT,
                                                                                                      padx=5)

        # 绘制自适应共享时间轴标尺
        self.time_axis = TimelineHeaderAxis(table_header, height=35)
        self.time_axis.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 20))

        ttk.Separator(station_col, orient="horizontal").pack(fill=tk.X, padx=5)

        # 滚动条容器
        self.scrollable_list = ScrollableFrame(station_col)
        self.scrollable_list.pack(fill=tk.BOTH, expand=True, pady=5)

    def get_thread_session(self) -> requests.Session:
        """获取或创建当前执行线程专属的 requests.Session 实例，保证并发完全线程隔离"""
        if not hasattr(self.thread_local, "session"):
            self.thread_local.session = requests.Session()
            # 在新会话中安全禁用 urllib3 SSL 证书警告
            requests.packages.urllib3.disable_warnings()
        return self.thread_local.session

    # ------------------ 日志读取与时间线历史还原 ------------------
    def get_log_file_by_date(self, log_date: date) -> str:
        return f"{LOG_FOLDER}/station_disconnect_{log_date.strftime('%Y%m%d')}.log"

    def read_ip_config(self, file_path: str) -> Tuple[List[Tuple[str, str, str]], str]:
        """解析配置文件，支持提取第三列作为特定的探测策略"""
        result = []
        if not os.path.exists(file_path):
            return result, f"文件 {file_path} 不存在！"
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
            if len(lines) < 2:
                return result, "文件格式错误，需包含表头和数据！"
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    strategy = parts[2] if len(parts) >= 3 else "AUTO"
                    result.append((parts[0], parts[1], strategy))
            return result, f"成功加载 {len(result)} 个站点"
        except Exception as e:
            return result, f"读取失败: {str(e)}"

    def reconstruct_history_from_logs(self):
        """解析物理日志还原最近24小时状态线"""
        open_offline_events: Dict[str, float] = {}

        for bar in self.timeline_bars.values():
            bar.offline_events.clear()
            bar.first_monitor_ts = None

        log_files = [
            self.get_log_file_by_date(self.yesterday),
            self.get_log_file_by_date(self.today)
        ]

        for station, _, _ in self.ip_list:
            self.station_current_status[station] = None
            self.station_first_status_time[station] = (None, "")

        for log_file in log_files:
            if not os.path.exists(log_file):
                continue
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or " - " not in line:
                            continue
                        parts = line.split(" - ")
                        if len(parts) < 3:
                            continue
                        full_log_time, station_part, status_msg = parts[0], parts[1], parts[2]
                        station_name = station_part.split("(")[0]

                        bar = self.timeline_bars.get(station_name)
                        if not bar:
                            continue

                        try:
                            dt = datetime.strptime(full_log_time, "%Y-%m-%d %H:%M:%S")
                            ts = dt.timestamp()
                            time_only = full_log_time.split(" ")[1]
                        except Exception:
                            continue

                        # 捕捉最早的日志时间戳作为监控起点
                        if bar.first_monitor_ts is None or ts < bar.first_monitor_ts:
                            bar.first_monitor_ts = ts

                        is_online = "正常" in status_msg
                        self.station_current_status[station_name] = is_online
                        self.station_first_status_time[station_name] = (is_online, time_only)

                        if not is_online:
                            if station_name not in open_offline_events:
                                open_offline_events[station_name] = ts
                        else:
                            if station_name in open_offline_events:
                                start_ts = open_offline_events[station_name]
                                bar.offline_events.append([start_ts, ts])
                                del open_offline_events[station_name]
            except Exception as e:
                logging.error(f"解析日志还原历史数据失败({log_file}): {e}")

        now = time.time()
        for station_name, start_ts in open_offline_events.items():
            self.timeline_bars[station_name].offline_events.append([start_ts, now])

        for station_name, bar in self.timeline_bars.items():
            is_currently_offline = station_name in open_offline_events
            bar.last_status = not is_currently_offline
            bar.last_status_time = now

    # ------------------ 并发网络检测与收集 ------------------
    def run_detect_task(self, station: str, ip: str, strategy: str) -> Tuple[str, str, bool, str]:
        strategy_upper = strategy.upper().strip()

        # 使用线程本地隔离的专属 Session
        session = self.get_thread_session()

        if strategy_upper == "HTTP":
            ok, msg = http_check(session, ip, timeout=TIMEOUT)
        elif strategy_upper.startswith("TCP"):
            port = 80
            if ":" in strategy_upper:
                try:
                    port = int(strategy_upper.split(":")[1])
                except ValueError:
                    pass
            ok, msg = tcp_check(ip, default_port=port, timeout=TIMEOUT)
        elif strategy_upper.startswith("PING"):
            ok, msg = ping_check(ip, timeout_ms=int(TIMEOUT * 1000))
        else:
            ok, msg = auto_check(session, ip)

        return station, ip, ok, msg

    def batch_check_ips(self):
        if not self.is_running or not self.ip_list:
            return

        futures_map = {}
        for station, ip, strategy in self.ip_list:
            future = self.thread_pool.submit(self.run_detect_task, station, ip, strategy)
            futures_map[future] = (station, ip)

        self.thread_pool.submit(self.collect_results_as_completed, futures_map)

    def collect_results_as_completed(self, futures_map: dict):
        # 1. 测算当前整点，判定是否需要写入整点状态心跳记录
        now_dt = datetime.now()
        current_hour = now_dt.hour
        write_heartbeat = False

        if self.last_heartbeat_hour is None or self.last_heartbeat_hour != current_hour:
            self.last_heartbeat_hour = current_hour
            write_heartbeat = True  # 触发整点心跳写入保护

        for future in as_completed(futures_map):
            if not self.is_running:
                break

            station, ip = futures_map[future]
            try:
                station, ip, ok, msg = future.result()
            except Exception as e:
                station, ip, ok, msg = station, ip, False, f"检测异常崩溃: {str(e)[:30]}"

            current_full_time = now_dt.strftime('%Y-%m-%d %H:%M:%S')
            current_time_only = now_dt.strftime('%H:%M:%S')

            status_desc = "正常连接" if ok else "断开连接"
            # 如果是心跳写入，添加“心跳”后缀标识
            heartbeat_suffix = " (心跳)" if write_heartbeat else ""
            log_msg_detail = status_desc + (f" ({msg})" if not ok else "")

            prev_status = self.station_current_status.get(station)

            # 2. 如果满足【状态发生变更】或者【到达下一个整点心跳时刻】，则写入磁盘文件
            if prev_status is None or prev_status != ok or write_heartbeat:
                log_msg = f"{current_full_time} - {station}({ip}) - {log_msg_detail}"
                try:
                    with open(self.get_log_file_by_date(date.today()), "a", encoding="utf-8") as f:
                        f.write(log_msg + "\n")
                except Exception as e:
                    logging.error(f"写入日志文件故障: {e}")

                logging.info(f"{current_time_only} - {station}({ip}) - {log_msg_detail}")

            self.update_queue.put(("single_update", station, ok))

    # ------------------ 定时调度 ------------------
    def _trigger_batch_check(self):
        if not self.is_running:
            return
        self.batch_check_ips()
        self.root.after(CHECK_INTERVAL * 1000, self._trigger_batch_check)

    def _start_time_axis_loop(self):
        try:
            self.time_axis.update_axis()
            for bar in self.timeline_bars.values():
                bar.redraw()
        except Exception as e:
            logging.error(f"重绘滑动视图发生异常: {e}")

        self.root.after(30000, self._start_time_axis_loop)

    def _schedule_date_check(self):
        current_date = date.today()
        if current_date != self.today:
            logging.info(f"检测到日期更替：{self.today} → {current_date}")
            self.yesterday = self.today
            self.today = current_date

        self.root.after(10000, self._schedule_date_check)

    # ------------------ UI 绘制与自适应适配 ------------------
    def _select_file(self):
        path = filedialog.askopenfilename(filetypes=[("配置文件", "*.config;*.txt")])
        if path:
            self.file_var.set(path)

    def _load_selected_file(self):
        file_path = self.file_var.get().strip()
        if not file_path:
            messagebox.showwarning("提示", "请选择有效的配置文件！")
            return
        if self.is_running:
            self._stop_monitor()
        self._load_config(file_path)

    def _clear_station_list(self):
        for widget in self.scrollable_list.scrollable_frame.winfo_children():
            widget.destroy()
        self.timeline_bars.clear()

    def _build_station_list_ui(self):
        self._clear_station_list()

        for idx, (station, ip, strategy) in enumerate(self.ip_list):
            row_frame = ttk.Frame(self.scrollable_list.scrollable_frame, padding=(6, 0))
            row_frame.pack(fill=tk.X, expand=True, pady=0)

            # 1. 站点名称 (新罗马字体 Times New Roman，宽度同步调整为10像素，左对齐)
            name_label = ttk.Label(row_frame, text=station, width=10, anchor=tk.W, font=("Times New Roman", 10, "bold"))
            name_label.pack(side=tk.LEFT, padx=5)

            # 2. 高精度滑动自适应时间线 (自适应水平拉满对齐)
            timeline_bar = PrecisionTimelineBar(row_frame, height=16)
            timeline_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 20))
            self.timeline_bars[station] = timeline_bar

            sep = ttk.Separator(self.scrollable_list.scrollable_frame, orient="horizontal")
            sep.pack(fill=tk.X, padx=5)

    def _load_config(self, file_path: str):
        def task():
            ips, msg = self.read_ip_config(file_path)
            self.update_queue.put(("load_config_done", ips, msg))

        self.thread_pool.submit(task)

    def _load_history_logs_async(self, station_names: List[str]):
        def task():
            self.reconstruct_history_from_logs()
            self.update_queue.put(("load_logs_done",))

        self.thread_pool.submit(task)

    def _start_monitor(self):
        if not self.ip_list:
            messagebox.showwarning("警告", "当前无有效配置！")
            return
        self.is_running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        self._trigger_batch_check()
        messagebox.showinfo("服务上线", f"监控正式启动，当前托管节点数：{len(self.ip_list)}。")

    def _stop_monitor(self):
        self.is_running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        messagebox.showinfo("服务暂停", "轮询检测已中断。")

    def _update_ui_states_bulk(self):
        """日志装载完成后，全量首绘一次视图"""
        self.time_axis.update_axis()
        for station, _, _ in self.ip_list:
            status = self.station_current_status.get(station)
            timeline = self.timeline_bars.get(station)
            if timeline and status is not None:
                timeline.record_status(status)
        self._update_summary_label()

    def _update_summary_label(self):
        """刷新看板顶部节点汇总指标，并自适应列出故障站点名称"""
        online_count = sum(1 for s, _, _ in self.ip_list if self.station_current_status.get(s) is True)

        # 提取当前所有状态为故障（False）的站点名称
        offline_stations = [s for s, _, _ in self.ip_list if self.station_current_status.get(s) is False]
        offline_count = len(offline_stations)

        # 动态构造故障详情信息，限制最大显示 5 个站名，避免大批量断线时撑爆 UI
        if offline_count > 0:
            if offline_count <= 5:
                stations_detail = f" ({', '.join(offline_stations)})"
            else:
                stations_detail = f" ({', '.join(offline_stations[:5])}... 等{offline_count}个)"
        else:
            stations_detail = ""

        total_nodes = len(self.ip_list)
        self.summary_label.config(
            text=f"节点总数: {total_nodes}  |  在线: {online_count}  |  故障: {offline_count}{stations_detail}"
        )

    def _process_queue(self):
        try:
            while not self.update_queue.empty():
                task = self.update_queue.get_nowait()
                action = task[0]
                if action == "load_config_done":
                    ips, msg = task[1], task[2]
                    if ips:
                        self.ip_list = ips
                        self._build_station_list_ui()
                        self._load_history_logs_async([s for s, _, _ in ips])
                    messagebox.showinfo("配置读取", msg)
                elif action == "load_logs_done":
                    self._update_ui_states_bulk()
                    for bar in self.timeline_bars.values():
                        bar.redraw()
                elif action == "single_update":
                    station, ok = task[1], task[2]
                    self.station_current_status[station] = ok
                    timeline = self.timeline_bars.get(station)
                    if timeline:
                        timeline.record_status(ok)
                    self._update_summary_label()
        except queue.Empty:
            pass
        self.root.after(100, self._process_queue)

    def graceful_exit(self):
        self.is_running = False
        self.thread_pool.shutdown(wait=False)
        # 本地线程 Session 将随线程销毁自动被垃圾回收机制释放
        try:
            sys.exit(0)
        except Exception:
            pass


if __name__ == "__main__":
    # 启用 High-DPI 适配支持
    try:
        from ctypes import windll

        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    try:
        requests.packages.urllib3.disable_warnings()

        main_window = tk.Tk()

        # 动态安全加载窗口左上角 ICO 图标
        icon_file = get_resource_path("app.ico")
        if os.path.exists(icon_file):
            try:
                main_window.iconbitmap(icon_file)
            except Exception:
                pass

        app = IPMonitorApp(main_window)

        main_window.protocol("WM_DELETE_WINDOW", lambda: (app.graceful_exit(), main_window.destroy()))
        main_window.mainloop()
    except Exception as general_err:
        logging.critical(f"系统故障引发退出: {general_err}")