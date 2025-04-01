#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# RTMP推流监控工具 v3.0 - 支持Windows/macOS/Linux

# ================= 初始化阶段 =================
import sys
import subprocess
import importlib
import os
import platform
from queue import Queue
from time import time
from threading import Thread, Event, Lock
from collections import deque


# ================= 依赖管理 =================
def setup_environment():
    """环境初始化与依赖安装"""
    required_packages = {
        'scapy': 'scapy',
        'pyperclip': 'pyperclip'
    }

    # 显示当前环境信息
    current_python = sys.executable
    print(f"🔧 当前Python路径: {current_python}")
    print(f"🖥️  操作系统: {platform.system()} {platform.release()}")

    # 安装缺失依赖
    for pkg, mod in required_packages.items():
        try:
            importlib.import_module(mod)
            print(f"✅ {pkg} 已就绪")
        except ImportError:
            print(f"⚙️ 正在安装 {pkg}...")
            try:
                subprocess.check_call([
                    current_python, '-m', 'pip', 'install',
                    '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple',
                    pkg
                ], stdout=subprocess.DEVNULL)
                print(f"✨ {pkg} 安装成功")
                time.sleep(2)  # 确保环境刷新
            except subprocess.CalledProcessError:
                print(f"❌ {pkg} 安装失败，请手动执行:")
                print(f"pip install {pkg}")
                sys.exit(1)


# ================= 主程序依赖 =================
setup_environment()

# 现在安全导入其他依赖
from scapy.all import sniff, Raw, get_working_ifaces, TCP, TCPSession
import struct
import re
import tkinter as tk
import pyperclip

# ================= 全局配置 =================
data_queue = Queue()
DEBUG_MODE = False  # 设为True显示调试信息


# ================= 跨平台工具 =================
def check_privileges():
    """跨平台权限检查"""
    system = platform.system()
    if system == 'Windows':
        try:
            # 尝试访问系统目录验证权限
            os.listdir(os.path.join(os.environ['SystemRoot'], 'System32'))
            return True
        except PermissionError:
            return False
        except:
            return True  # 其他错误视为有权限
    else:
        return os.geteuid() == 0


def get_active_interface():
    """智能选择网络接口"""
    system = platform.system()
    try:
        # Windows优先选择以太网适配器（中英文兼容）
        if system == 'Windows':
            for iface in get_working_ifaces():
                desc = iface.description.lower()
                if '以太网' in desc or 'ethernet' in desc:
                    return iface.name
            return get_working_ifaces()[0].name

        # macOS排除虚拟接口
        elif system == 'Darwin':
            exclude = ['awdl', 'llw', 'utun', 'bridge', 'vmenet']
            for iface in get_working_ifaces():
                if not any(p in iface.name for p in exclude) and iface.ip:
                    return iface.name
            return 'en0'

        # Linux选择eth0
        else:
            return 'eth0'
    except Exception as e:
        print(f"⚠️  接口选择失败: {str(e)}")
        return 'eth0'  # 保底默认值


# ================= 增强解析引擎 =================
class RTMPAIEngine:
    def __init__(self):
        self.stream_history = deque(maxlen=10)  # 扩大历史记录容量
        self.url_history = deque(maxlen=5)
        self.last_valid_stream = None
        self.stable_counter = 0

    def extract_swf_url(self, raw: bytes) -> str:
        """增强地址解析"""
        try:
            # 优化匹配模式
            patterns = [
                (b'\x02\x00\x06tcUrl\x00\x02', 11),
                (b'\x02\x00\x06swfUrl\x00\x02', 12),
                (b'rtmp://', 0),
                (b'//', 0)  # 匹配更简洁的URL格式
            ]

            for pattern, offset in patterns:
                if (pos := raw.find(pattern)) != -1:
                    start = pos + offset
                    end = raw.find(b'\x00', start) or raw.find(b'?', start) or start + 128
                    url = raw[start:end].decode('utf-8', 'ignore').strip('\x00')
                    if 10 < len(url) < 128:
                        self.url_history.append(url)
                        return url
            return self.url_history[-1] if self.url_history else None
        except Exception as e:
            print(f"URL解析异常: {str(e)}")
            return None

    def extract_stream(self, raw: bytes) -> str:
        """增强流解析"""
        try:
            # 优先检查历史缓存
            if self.last_valid_stream and (self.last_valid_stream.encode() in raw):
                self.stable_counter += 1
                if self.stable_counter >= 2:  # 降低稳定阈值
                    return self.last_valid_stream

            # 改进参数捕获
            stream_id = self._find_stream_id(raw)
            params = self._enhanced_param_parse(raw)

            if self._validate_stream(stream_id, params):
                stream = self._build_stream(stream_id, params)
                self._update_history(stream)
                return stream
            return None
        except Exception as e:
            print(f"流解析异常: {str(e)}")
            return None

    def _find_stream_id(self, raw: bytes) -> str:
        """改进流ID发现"""
        # 扩展匹配模式
        patterns = [
            rb'stream-(\d{15,20})\?',  # 标准带问号
            rb'stream-([a-f\d]{24,32})\?',
            rb'stream/(\d+)[/\?]',  # 支持路径型格式
            rb'id=(\d{15,20})'  # 备用ID定位
        ]
        for pattern in patterns:
            if match := re.search(pattern, raw):
                return match.group(1).decode()
        return None

    def _enhanced_param_parse(self, raw: bytes) -> dict:
        """增强参数解析"""
        params = {}
        # 扩展参数匹配规则
        param_rules = {
            'expire': [
                rb'[?&]expire=(\d{10})\b',
                rb'expire=(\d{10})(?:&|$)'
            ],
            'sign': [
                rb'[?&]sign=([a-fA-F0-9]{32})\b',
                rb'signature=([a-fA-F0-9]{32})'
            ],
            'volcSecret': [
                rb'[?&]volcSecret=([a-fA-F0-9]{32})\b',
                rb'secret=([a-fA-F0-9]{32})'
            ],
            'volcTime': [
                rb'[?&]volcTime=(\d{10})\b',
                rb'time=(\d{10})'
            ]
        }

        for param, patterns in param_rules.items():
            for pattern in patterns:
                if match := re.search(pattern, raw):
                    params[param] = match.group(1).decode()
                    break
        return params

    def _validate_stream(self, stream_id: str, params: dict) -> bool:
        """增强流验证"""
        try:
            # 基础检查
            if not stream_id or not params.get('expire') or not params.get('sign'):
                return False

            # 时间戳范围检查（允许前后一年）
            current_time = int(time())
            expire = int(params['expire'])
            if not (current_time - 31536000 < expire < current_time + 31536000):
                return False

            # 签名格式验证
            if not re.fullmatch(r'^[a-fA-F0-9]{32}$', params['sign']):
                return False

            return True
        except:
            return False

    def _build_stream(self, stream_id: str, params: dict) -> str:
        """智能构建推流码"""
        base = f"stream-{stream_id}?expire={params['expire']}&sign={params['sign'].lower()}"  # 统一小写签名

        # 可选参数动态附加
        optional = []
        if volcSecret := params.get('volcSecret'):
            optional.append(f"volcSecret={volcSecret.lower()}")
        if volcTime := params.get('volcTime'):
            optional.append(f"volcTime={volcTime}")

        return f"{base}&{'&'.join(optional)}" if optional else base

    def _update_history(self, stream: str):
        """更新历史记录"""
        self.stream_history.append(stream)
        self.last_valid_stream = stream
        self.stable_counter = 0


# ================= 增强监控界面 =================
class EnhancedMonitor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RTMP智能监控 v10.1")
        self.geometry("1000x400")
        self.engine = RTMPAIEngine()
        self._create_ui()
        self._init_system()
        self.protocol("WM_DELETE_WINDOW", self.safe_exit)

    def _create_ui(self):
        """创建增强界面"""
        # 服务器面板
        self.server_panel = self._create_info_panel("服务器地址", 0)
        # 推流码面板
        self.stream_panel = self._create_info_panel("推流码", 1)
        # 控制面板
        self._create_control_panel()
        # 状态栏
        self.status = tk.Label(self, text="🟢 系统就绪", font=('等线', 10), anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X, padx=10)

    def _create_info_panel(self, title: str, row: int) -> tk.Entry:
        """创建信息面板"""
        frame = tk.LabelFrame(self, text=title, font=('微软雅黑', 10))
        frame.pack(pady=5, padx=10, fill=tk.X)
        entry = tk.Entry(frame, width=100, font=('Consolas', 10), state='readonly')
        entry.pack(padx=5, pady=2, fill=tk.X)
        tk.Button(frame, text="📋", command=lambda: self.copy_content(entry.get()),
                  font=('等线', 10)).pack(side=tk.RIGHT, padx=5)
        return entry

    def _create_control_panel(self):
        """创建控制面板"""
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        self.start_btn = tk.Button(btn_frame, text="▶ 启动监控", command=self.restart_engine)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🔄 强制刷新", command=self.force_refresh).pack(side=tk.LEFT)
        tk.Button(btn_frame, text="⚙️ 重置系统", command=self.full_reset).pack(side=tk.LEFT)  # 改名并增强重置功能

    def full_reset(self):
        """完整系统重置"""
        # 清空界面
        self.server_panel.config(state='normal')
        self.server_panel.delete(0, tk.END)
        self.server_panel.config(state='readonly')
        self.stream_panel.config(state='normal')
        self.stream_panel.delete(0, tk.END)
        self.stream_panel.config(state='readonly')

        # 重置引擎
        self.engine = RTMPAIEngine()
        self.update_status("🟣 系统已完全重置")

    def _init_system(self):
        """初始化系统"""
        self.packet_queue = Queue(maxsize=100)
        self.stop_event = Event()
        self.capture_thread = None
        self.restart_engine()

    def restart_engine(self):
        """重启捕获引擎"""
        if self.capture_thread and self.capture_thread.is_alive():
            self.stop_event.set()
            self.capture_thread.join(timeout=1)

        self.stop_event.clear()
        self.capture_thread = Thread(target=self.capture_engine)
        self.capture_thread.start()
        self.after(300, self.update_loop)

    def capture_engine(self):
        """增强捕获引擎"""
        try:
            iface = get_active_interface()
            print(f"🕵️ 正在监控接口: {iface}")  # 调试信息
            sniff(iface=iface,
                  filter="tcp port 1935",
                  prn=self.process_packet,
                  session=TCPSession,
                  stop_filter=lambda _: self.stop_event.is_set(),
                  store=0,
                  timeout=None)  # 修改为持续监听
        except Exception as e:
            self.update_status(f"🔴 捕获错误: {str(e)}")
            print(f"❌ 捕获异常: {traceback.format_exc()}")  # 打印完整错误信息

    def process_packet(self, packet):
        """数据包处理"""
        if Raw in packet and not self.stop_event.is_set():
            try:
                raw = bytes(packet[Raw].load)
                if DEBUG_MODE:
                    print(f"📦 捕获到 {len(raw)} 字节数据")
                    with open("packet_debug.bin", "ab") as f:
                        f.write(raw)
                self.packet_queue.put_nowait(raw)
            except Exception as e:
                print(f"处理数据包出错: {str(e)}")

    def update_loop(self):
        """增强更新循环"""
        try:
            processed = 0
            while not self.packet_queue.empty() and processed < 8:  # 每次处理最多8个包
                raw = self.packet_queue.get()
                self.process_data(raw)
                processed += 1

            # 自动恢复显示
            if not self.stream_panel.get() and self.engine.last_valid_stream:
                self.stream_panel.config(state='normal')
                self.stream_panel.delete(0, tk.END)
                self.stream_panel.insert(0, self.engine.last_valid_stream)
                self.stream_panel.config(state='readonly')
                self.update_status("🟡 使用缓存数据")

            if not self.stop_event.is_set():
                self.after(200, self.update_loop)
        except Exception as e:
            self.update_status(f"🔴 更新失败: {str(e)}")

    def process_data(self, raw: bytes):
        """数据处理"""
        # 更新服务器地址
        if url := self.engine.extract_swf_url(raw):
            self.server_panel.config(state='normal')
            self.server_panel.delete(0, tk.END)
            self.server_panel.insert(0, url)
            self.server_panel.config(state='readonly')

        # 更新推流码
        if stream := self.engine.extract_stream(raw):
            self.stream_panel.config(state='normal')
            self.stream_panel.delete(0, tk.END)
            self.stream_panel.insert(0, stream)
            self.stream_panel.config(state='readonly')
            self.update_status(f"🟢 更新于 {time()}")

    def force_refresh(self):
        """强制刷新界面"""
        self.server_panel.config(state='normal')
        self.server_panel.delete(0, tk.END)
        self.server_panel.config(state='readonly')
        self.stream_panel.config(state='normal')
        self.stream_panel.delete(0, tk.END)
        self.stream_panel.config(state='readonly')
        self.update_status("🟡 界面已强制刷新")

    def copy_content(self, text: str):
        """安全复制"""
        try:
            pyperclip.copy(text)
            self.update_status("📋 复制成功")
        except Exception as e:
            self.update_status(f"🔴 复制失败: {str(e)}")

    def update_status(self, message: str):
        """更新状态"""
        color_map = {
            "🟢": "#00FF00",
            "🔵": "#00FFFF",
            "🟠": "#FFA500",
            "🔴": "#FF0000",
            "🟡": "#FFFF00",
            "🟣": "#FF00FF"
        }
        # 正确提取第一个字符作为emoji标识
        emoji_char = message[0] if message else ''
        color = color_map.get(emoji_char, "black")
        self.status.config(text=message, fg=color)

    def safe_exit(self):
        """安全退出"""
        print("\n🛑 正在关闭...")
        self.stop_event.set()

        # 强制终止sniff线程
        if self.capture_thread and self.capture_thread.is_alive():
            print("🛑 正在终止抓包线程...")
            self.capture_thread.join(timeout=1.5)  # 延长等待时间
            if self.capture_thread.is_alive():
                print("⚠️ 强制终止残留线程")

        # 彻底销毁窗口
        self.destroy()

        # 确保进程退出
        os._exit(0)  # 强制退出


# ================= 主程序入口 =================
if __name__ == "__main__":
    # 权限验证
    if not check_privileges():
        print("❌ 需要管理员权限运行！")
        if platform.system() == 'Windows':
            print("请右键选择'以管理员身份运行'")
        sys.exit(1)

    # 启动应用
    app = EnhancedMonitor()
    app.mainloop()
