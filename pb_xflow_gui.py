#==============================================================#
# File       :   pb_xflow_gui.py
# Ctime      :   2025-10-16
# Mtime      :   2026-10-19
# Version    :   PB XFlow GUI（调用同目录 pb_xflow.exe）
# Author     :   www.linkleading.com
# Copyright (C) 2025-2026
#==============================================================#
# -*- coding: utf-8 -*-
"""
PB X-Flow GUI（常量/引擎逻辑 + PyQt6 界面）
功能对等 pb_fast_copy_gui_v123.cpp
引擎 exe 可为 PB_X_Flow_Core.exe / pb_xflow.exe 等（见 ENGINE_CANDIDATES），与脚本同目录优先。
2026-4-14
"""
import os
import sys
import re
import codecs
import locale
import subprocess
import threading
import queue
import time
from pathlib import Path
from datetime import datetime
from collections import deque
from configparser import ConfigParser

try:
    import winreg
except ImportError:
    winreg = None  # type: ignore

# 引擎管道输出已强制 _O_U8TEXT；与控制台 ACP 解耦，统一 UTF-8
ENGINE_STDOUT_ENCODING = 'utf-8'
# get_base_paths() 会 chdir 到 exe 目录；保留启动 CWD 以解析相对路径 argv
ORIG_CWD = os.getcwd()

# 配置
CONFIG_FILENAME = "pb_xflow.ini"
ENGINE_EXE = "PB_X_Flow_Core.exe"
# 与 build_pb_xflow.bat 产物 pb_xflow.exe 等兼容（元组逗号不可省，否则成字符串）
ENGINE_CANDIDATES = (
    "PB_X_Flow_Core.exe",
    "pb_xflow.exe",
    "fast_copy_universal_v122.exe",
)
TELEMETRY_STOP_EVENT = "Local\\XFlow_Stop_Event_"
TELEMETRY_PAUSE_RELEASE = "Local\\XFlow_PauseRelease_Event_"
LOG_RETENTION_DAYS = 7
MAX_LOG_LINES = 5000
AUTO_SAVE_INTERVAL_MS = 30000

# 右键菜单 / 关于（与 pb_xdelete_gui 对齐）
REG_KEY_NAME = "PB_XFlow_GUI"
MENU_NAME = "⚡ PB X-Flow (以该目录为源)"
MANUAL_FILE_NAME = "PB_XFlow_Manual.pdf"
ICON_NAME = "lflogo.ico"
KNOWN_NON_PATH_ARGS = frozenset(("--reg-menu", "--help", "-h", "/?", "-?", "-defender-exclude"))

# 副实例 → 主实例路径交接（对齐 XDelete；%TEMP%\PB_XFlow_IPC）
import tempfile as _tempfile
PENDING_PATHS_DIR = os.path.join(_tempfile.gettempdir(), "PB_XFlow_IPC")


# 单实例 Mutex（与 pb_xdelete_gui 思路一致；进程退出由系统释放句柄）
APP_INSTANCE_MUTEX_NAME = "Local\\PB_XFlow_GUI_Unique_V1"
_XFLOW_MUTEX_HANDLE = None

COPYRIGHT_TEXT = (
    "PB X-Flow GUI\n"
    "Copyright © 2025-2026 Wuhan Linkleading\n"
    "All rights reserved.\n\n"
    "本软件用于企业级海量文件复制与同步；\n"
    "使用本软件即表示您已阅读并接受许可条款。"
)


def get_base_paths():
    """与 pb_xdelete_gui 一致：壳菜单注册与启动入口必须以 sys.argv[0] 为准（exe 或 .py），避免 __file__ 与 onefile 错位。"""
    try:
        real_exe_path = os.path.abspath(sys.argv[0])
        base_dir = os.path.dirname(real_exe_path) or os.getcwd()
        try:
            os.chdir(base_dir)
        except OSError:
            pass
        return base_dir, real_exe_path
    except Exception:
        return os.getcwd(), os.path.abspath(sys.executable)


BASE_DIR, REAL_EXE_PATH = get_base_paths()


def _is_frozen_or_compiled_module():
    """判断是否为打包/编译启动（图标解压目录、引擎探测等）。"""
    if getattr(sys, "frozen", False):
        return True
    if "__compiled__" in globals():
        return True
    try:
        import __main__ as _m

        if getattr(_m, "__compiled__", None) or "__compiled__" in getattr(_m, "__dict__", {}):
            return True
    except Exception:
        pass
    return False


def try_acquire_single_instance_mutex():
    """Windows 下创建 Local\\ Mutex；已存在则返回 False。64 位 HANDLE 安全。非 Windows 恒为 True。"""
    global _XFLOW_MUTEX_HANDLE
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        mutex = kernel32.CreateMutexW(None, True, APP_INSTANCE_MUTEX_NAME)
        if not mutex:
            return False  # fail-closed：无法创建则拒绝多开风险路径
        err = kernel32.GetLastError()
        if err == 0x000000B7:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(mutex)
            return False
        _XFLOW_MUTEX_HANDLE = mutex
        return True
    except Exception:
        return True


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _manual_candidates():
    bases = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            bases.append(meipass)
        try:
            d = os.path.dirname(os.path.dirname(os.path.abspath(__import__("PyQt6").__file__)))
            bases.append(d)
        except Exception:
            pass
    bases.append(BASE_DIR)
    try:
        bases.append(os.path.dirname(os.path.abspath(__file__)))
    except NameError:
        pass
    seen = set()
    out = []
    for b in bases:
        if not b or b in seen:
            continue
        seen.add(b)
        out.append(os.path.join(b, MANUAL_FILE_NAME))
    return out


def do_reg_context_menu():
    """在「文件夹」右键添加「PB X-Flow」；与 pb_xdelete_gui.do_reg_menu 相同写法（命令仅一项可执行路径 + %1）。"""
    if winreg is None:
        raise RuntimeError("winreg 不可用（非 Windows）")

    key = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\{REG_KEY_NAME}")
    winreg.SetValue(key, "", winreg.REG_SZ, MENU_NAME)
    # 图标：优先 lflogo.ico（与资源管理器壳菜单显示一致）；否则退回 argv[0]（exe 自带图标）
    _ico = get_icon_path()
    _icon_val = _ico if (_ico and os.path.isfile(_ico)) else REAL_EXE_PATH
    winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, _icon_val)
    winreg.SetValueEx(key, "MultiSelectModel", 0, winreg.REG_SZ, "Player")
    winreg.CloseKey(key)

    key_cmd = winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\{REG_KEY_NAME}\\command")
    if _is_frozen_or_compiled_module():
        cmd_str = f'"{REAL_EXE_PATH}" "%1"'
    else:
        pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        exe = pyw if os.path.isfile(pyw) else sys.executable
        cmd_str = f'"{exe}" "{REAL_EXE_PATH}" "%1"'
    winreg.SetValue(key_cmd, "", winreg.REG_SZ, cmd_str)
    winreg.CloseKey(key_cmd)


def do_unreg_context_menu():
    """移除文件夹右键菜单项"""
    if winreg is None:
        raise RuntimeError("winreg 不可用（非 Windows）")
    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\{REG_KEY_NAME}\\command")
    except FileNotFoundError:
        pass
    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, f"Directory\\shell\\{REG_KEY_NAME}")
    except FileNotFoundError:
        pass

# 共享内存遥测常量（与 ipc_telemetry.h 一致）
LOG_RING_SIZE = 4 * 1024 * 1024
# SharedTelemetry 实际为 224 字节；运行时以 ctypes.sizeof 为准
TELEMETRY_SHM_BYTES = 224
SHARED_LOG_RING_META_SIZE = 128
TELEMETRY_SHM_PREFIX = "Local\\PBXFlow_Telemetry_"
LOG_RING_BUF_SUFFIX = "_LogRingBuf"
LOG_RING_SHM_SUFFIX = "_LogRing"
LOG_RING_EVENT_PREFIX = "Local\\PBXFlow_LogRing_Event_"

# 场景预设（与 SCENARIO_PARAMS.md 对应）
SCENARIOS = {
    "A": {
        # PB 极限吞吐：-F 跳过 ACL/ADS；引擎另支持 -no_ads。要校验用 -J -X（批内哈希+异步 Verify）
        "name": "A: 海量小文件极速迁移",
        "entries": {"threads": "24", "buffer": "32", "ioring_batch": "512", "queue": "100000", "bigqd": "0"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "bfs": True},
    },
    "B": {
        "name": "B: 超大文件/数据库备份",
        "entries": {"threads": "64", "buffer": "64", "ioring_batch": "256", "queue": "20000", "bigqd": "8",
                    "checkpoint_interval": "300", "checkpoint_gb": "100"},
        "checks": {"fast": True, "ioring": True, "affinity": True},
    },
    "C": {
        "name": "C: 复杂混合业务整体迁移",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "50000", "bigqd": "8"},
        "checks": {"fast": True, "ioring": True, "affinity": True},
    },
    "D": {
        "name": "D: 生产环境在线平滑迁移",
        "entries": {"threads": "48", "buffer": "32", "ioring_batch": "256", "queue": "30000", "bigqd": "4",
                    "speed": "100", "checkpoint_interval": "300", "checkpoint_gb": "100"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "host_aware": True, "lowio": True},
    },
    "E": {
        "name": "E: 超深目录/极速清理",
        "entries": {},
        "checks": {},
        "mode": "delete",
    },
    "F": {
        "name": "F: UNC/NAS 网络迁移",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "30000", "bigqd": "16"},
        "checks": {"fast": True, "ioring": True, "affinity": True},
    },
    "G": {
        "name": "G: MFT 极速扫描(百万级/秒)",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "50000", "bigqd": "8"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "mft_scan": True, "mft_raw": True},
    },
    "H": {
        "name": "H: 增量/差异同步(Delta)",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "50000", "bigqd": "8",
                    "checkpoint_interval": "300", "checkpoint_gb": "100"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "delta": True},
    },
    "I": {
        "name": "I: 镜像同步",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "50000", "bigqd": "8"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "mirror": True},
    },
    "J": {
        "name": "J: 合规/审计(全量校验)",
        "entries": {"threads": "48", "buffer": "32", "ioring_batch": "256", "queue": "30000", "bigqd": "4"},
        "checks": {"fast": False, "ioring": True, "affinity": True, "acl": True, "perfect": True, "verifyinfo": True},
        "verify": "XXH3",
    },
    "K": {
        "name": "K: 定时窗口迁移(-b/-e)",
        "entries": {"threads": "64", "buffer": "32", "ioring_batch": "256", "queue": "50000", "bigqd": "8",
                    "starth": "22", "endh": "6", "idle": "16"},
        "checks": {"fast": True, "ioring": True, "affinity": True, "rh_strict": True},
    },
    "L": {
        "name": "L: DirectIO 大文件(绕过缓存)",
        "entries": {"threads": "64", "buffer": "64", "ioring_batch": "256", "queue": "30000", "bigqd": "8",
                    "directio": "100"},
        "checks": {"fast": True, "ioring": True, "affinity": True},
    },
}

# Windows API (ctypes) 用于停止/暂停 + 共享内存遥测
try:
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.windll.kernel32
    CreateEventW = kernel32.CreateEventW
    CreateEventW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR]
    CreateEventW.restype = wintypes.HANDLE
    SetEvent = kernel32.SetEvent
    ResetEvent = kernel32.ResetEvent
    SetEvent.argtypes = [wintypes.HANDLE]
    SetEvent.restype = wintypes.BOOL
    ResetEvent.argtypes = [wintypes.HANDLE]
    ResetEvent.restype = wintypes.BOOL
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    WaitForSingleObject.restype = wintypes.DWORD
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    WAIT_FAILED = 0xFFFFFFFF
    CloseHandle = kernel32.CloseHandle
    GetCurrentProcessId = kernel32.GetCurrentProcessId
    GetCurrentProcessId.restype = wintypes.DWORD
    # 共享内存
    CreateFileMappingW = kernel32.CreateFileMappingW
    CreateFileMappingW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPCWSTR]
    CreateFileMappingW.restype = wintypes.HANDLE
    MapViewOfFile = kernel32.MapViewOfFile
    MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_size_t]
    MapViewOfFile.restype = wintypes.LPVOID
    UnmapViewOfFile = kernel32.UnmapViewOfFile
    UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
    UnmapViewOfFile.restype = wintypes.BOOL
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    PAGE_READWRITE = 0x04
    FILE_MAP_READ = 0x0004
    FILE_MAP_WRITE = 0x0002

    # 与 ipc_telemetry.h SharedTelemetry / TelemetryData 对齐（pack=1）
    class TelemetryData(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("magic", ctypes.c_uint32),
            ("totalFiles", ctypes.c_uint64),
            ("copiedFiles", ctypes.c_uint64),
            ("totalBytes", ctypes.c_uint64),
            ("copiedBytes", ctypes.c_uint64),
            ("currentSpeedMBps", ctypes.c_uint32),
            ("activeThreads", ctypes.c_uint32),
            ("isFinished", ctypes.c_uint32),
            ("version", ctypes.c_uint16),
            ("ack_SpeedLimit", ctypes.c_uint8),
            ("ack_Pause", ctypes.c_uint8),
            ("cmd_Pause", ctypes.c_uint32),
            ("cmd_SpeedLimit", ctypes.c_uint32),
            ("cmd_Cancel", ctypes.c_uint32),
            ("eta_seconds", ctypes.c_uint32),
            ("failedFiles", ctypes.c_uint32),
            ("io_block_clone", ctypes.c_uint64),
            ("io_direct_big", ctypes.c_uint64),
            ("io_buffered_big", ctypes.c_uint64),
        ]

    class SharedTelemetry(ctypes.Structure):
        _pack_ = 1
        _fields_ = [
            ("seq", ctypes.c_long),
            ("_pad1", ctypes.c_char * 60),
            ("isDirty", ctypes.c_uint8),
            ("_pad2", ctypes.c_char * 63),
            ("data", TelemetryData),
        ]

    TELEMETRY_SHM_BYTES = ctypes.sizeof(SharedTelemetry)
    HAS_CTYPES = True
except Exception:
    HAS_CTYPES = False
    INVALID_HANDLE_VALUE = -1
    TelemetryData = None  # type: ignore
    SharedTelemetry = None  # type: ignore

# 与 ipc_telemetry.h TELEMETRY_MAGIC（"FAST"）一致，供 GUI 读取遥测快照校验
TELEMETRY_MAGIC = 0x46415354


def get_config_path():
    """%APPDATA%\\PB_XFlow\\pb_xflow.ini"""
    appdata = os.environ.get("APPDATA", ".")
    cfg_dir = os.path.join(appdata, "PB_XFlow")
    os.makedirs(cfg_dir, exist_ok=True)
    return os.path.join(cfg_dir, CONFIG_FILENAME)


def get_log_dir():
    """%APPDATA%\\PB_XFlow\\Logs"""
    appdata = os.environ.get("APPDATA", ".")
    log_dir = os.path.join(appdata, "PB_XFlow", "Logs")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def find_engine_path():
    """查找引擎 exe：多维度路径探测，彻底解决 UAC 和 Onefile 导致的工作目录漂移"""
    bases = []
    
    # 1. 编译环境的真实运行时目录 / Nuitka 临时解压目录
    try:
        bases.append(Path(__file__).resolve().parent)
    except Exception:
        pass
        
    # 2. 用户双击的真实 exe 所在目录 (Nuitka 环境)
    if "__compiled__" in globals() or getattr(sys, "frozen", False):
        bases.append(Path(sys.executable).parent)
        try:
            bases.append(Path(sys.argv[0]).resolve().parent)
        except Exception:
            pass
            
    # 3. PyInstaller 兼容 (防患于未然)
    if hasattr(sys, "_MEIPASS"):
        bases.append(Path(sys._MEIPASS))

    bases.append(Path(BASE_DIR))

    # 5. 保底当前工作目录
    bases.append(Path.cwd())
    
    seen = set()
    for base in bases:
        if not base or base in seen:
            continue
        seen.add(base)
        for name in ENGINE_CANDIDATES:
            exe = base / name
            if exe.exists():
                return str(exe.resolve())
    return ENGINE_CANDIDATES[0]


def _resource_dir():
    """与 pb_xdelete_gui 一致：打包资源根（PyInstaller _MEIPASS / Nuitka onefile 解压目录）。"""
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return meipass
        try:
            d = os.path.dirname(os.path.dirname(os.path.abspath(__import__("PyQt6").__file__)))
            if d and os.path.isdir(d) and any(os.path.isfile(os.path.join(d, n)) for n in ENGINE_CANDIDATES):
                return d
        except Exception:
            pass
        try:
            d = os.path.dirname(os.path.abspath(__file__))
            if d:
                return d
        except NameError:
            pass
        return BASE_DIR
    return BASE_DIR


def get_icon_path():
    """与 pb_xdelete.get_icon_path 一致；壳菜单 Icon 字段用 .ico 路径时显示自定义图标。"""
    if getattr(sys, "frozen", False):
        p = os.path.join(_resource_dir(), ICON_NAME)
        if os.path.isfile(p):
            return os.path.abspath(p)
    path = os.path.join(BASE_DIR, ICON_NAME)
    if os.path.isfile(path):
        return os.path.abspath(path)
    try:
        p2 = os.path.join(os.path.dirname(os.path.abspath(__file__)), ICON_NAME)
        if os.path.isfile(p2):
            return os.path.abspath(p2)
    except Exception:
        pass
    if _is_frozen_or_compiled_module():
        try:
            d = os.path.dirname(os.path.dirname(os.path.abspath(__import__("PyQt6").__file__)))
            p3 = os.path.join(d, ICON_NAME)
            if os.path.isfile(p3):
                return os.path.abspath(p3)
        except Exception:
            pass
    return ""


def escape_path_for_cmd(path):
    """路径含 " 时转义为 """""
    if not path:
        return ""
    return path.replace('"', '""')


def parse_progress_speed(line):
    """从动态行解析进度和速度（复制模式提取MB/s，销毁模式提取项/s）"""
    prog, speed = 0.0, 0.0
    perc = re.search(r'(\d+\.?\d*)\s*%', line)
    if perc:
        try:
            prog = float(perc.group(1))
            if prog > 100:
                prog = 0
        except ValueError:
            pass

    gb = re.search(r'(\d+\.?\d*)\s*GB/s', line, re.I)
    if gb:
        try:
            speed = float(gb.group(1)) * 1024.0
        except ValueError:
            pass

    if speed <= 0:
        mb = re.search(r'(\d+\.?\d*)\s*MB/s', line)
        if mb:
            try:
                speed = float(mb.group(1))
            except ValueError:
                pass

    # [新增] 适配极速销毁模式的速度解析：Avg: 3964/s
    if speed <= 0:
        items_sec = re.search(r'Avg:\s*(\d+)/s', line)
        if items_sec:
            try:
                speed = float(items_sec.group(1))
            except ValueError:
                pass

    return prog, speed


def is_error_line(line):
    """判断是否为错误行。
    勿用裸子串 FAILED：引擎 [DEBUG] main_loop_exit 含 Failed=0 会误判为失败并污染审计报告。"""
    if not line or not line.strip():
        return False
    u = line.upper()
    if "[DEBUG]" in line or "MAIN_LOOP_EXIT" in u:
        return False
    if "[ERR]" in line or "Err:" in line:
        return True
    # 统计字段 Failed=123，非“操作失败”语义
    if re.search(r"\bFAILED\s*=\s*\d+", line, re.I):
        return False
    return "FAILED" in u





def write_pending_paths(paths):
    """副进程：将目录路径写入 PENDING_PATHS_DIR，供主进程设为源。"""
    if not paths:
        return
    filtered = []
    for p in paths:
        if not p or p.strip() in KNOWN_NON_PATH_ARGS:
            continue
        if p.startswith("-") and len(p) > 1 and p not in ("-",):
            continue
        filtered.append(p.strip().strip('"'))
    if not filtered:
        return
    try:
        os.makedirs(PENDING_PATHS_DIR, exist_ok=True)
        fname_final = os.path.join(PENDING_PATHS_DIR, f"_{os.getpid()}_{id(paths)}.tmp")
        fname_writing = fname_final + ".writing"
        with open(fname_writing, "w", encoding="utf-8") as f:
            for p in filtered:
                f.write(p + "\n")
        os.rename(fname_writing, fname_final)
    except Exception:
        pass


def cleanup_pending_paths_old_files():
    if not os.path.isdir(PENDING_PATHS_DIR):
        return
    import time as _time
    now = _time.time()
    try:
        for name in os.listdir(PENDING_PATHS_DIR):
            if not (name.endswith(".tmp") or name.endswith(".writing")):
                continue
            fpath = os.path.join(PENDING_PATHS_DIR, name)
            try:
                if now - os.path.getmtime(fpath) > 3600:
                    os.remove(fpath)
            except Exception:
                pass
    except Exception:
        pass


def process_pending_paths(window):
    """主进程：消费 pending；运行中不消费。将目录写入 entry_src。"""
    if not os.path.isdir(PENDING_PATHS_DIR):
        return 0
    if getattr(window, "is_running", False):
        return 0
    added = 0
    last_dir = None
    try:
        for name in os.listdir(PENDING_PATHS_DIR):
            if not name.endswith(".tmp"):
                continue
            fpath = os.path.join(PENDING_PATHS_DIR, name)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        p = line.strip()
                        if not p:
                            continue
                        if not os.path.isabs(p):
                            p = os.path.abspath(os.path.join(ORIG_CWD, p))
                        if os.path.isdir(p):
                            last_dir = os.path.normpath(p)
                            added += 1
            except Exception:
                pass
            try:
                os.remove(fpath)
            except Exception:
                pass
    except Exception:
        pass
    if last_dir and hasattr(window, "entry_src"):
        try:
            window.entry_src.setText(last_dir)
            window.showNormal()
            window.activateWindow()
            window.raise_()
        except Exception:
            pass
    return added



def main():
    if sys.platform == "win32" and not try_acquire_single_instance_mutex():
        # 副实例：交接路径后秒退，不弹阻塞 MessageBox
        write_pending_paths(sys.argv[1:])
        sys.exit(0)

    from pb_xflow_gui_qt import run_qt_app

    try:
        os.makedirs(PENDING_PATHS_DIR, exist_ok=True)
        cleanup_pending_paths_old_files()
    except Exception:
        pass

    initial_src = None
    for a in sys.argv[1:]:
        if not a or a in KNOWN_NON_PATH_ARGS:
            continue
        if a.startswith("-") and len(a) > 1:
            continue
        p = a.strip().strip('"')
        if not os.path.isabs(p):
            p = os.path.abspath(os.path.join(ORIG_CWD, p))
        if os.path.isdir(p):
            initial_src = os.path.normpath(p)
            break
    sys.exit(run_qt_app(initial_src))


if __name__ == "__main__":
    if sys.platform == "win32" and "--reg-menu" in sys.argv:
        from PyQt6.QtWidgets import QApplication, QMessageBox
        from PyQt6.QtGui import QFont

        app = QApplication(sys.argv)
        app.setFont(QFont("Microsoft YaHei UI", 10))
        try:
            app.setStyle("Fusion")
        except Exception:
            pass
        app.setStyleSheet(
            "QMessageBox { background-color: #252526; }"
            "QMessageBox QLabel { color: #f0f0f0; background-color: transparent; font-size: 13px; }"
            "QMessageBox QPushButton { min-width: 76px; padding: 6px 14px; background-color: #3e3e42; color: #f0f0f0; "
            "border: 1px solid #555; border-radius: 4px; font-weight: bold; }"
            "QMessageBox QPushButton:hover { background-color: #505050; }"
        )
        if not is_admin():
            QMessageBox.critical(None, "错误", "需要管理员权限才能注册右键菜单。")
            sys.exit(1)
        try:
            do_reg_context_menu()
            QMessageBox.information(None, "成功", "右键菜单已添加！")
        except Exception as e:
            QMessageBox.critical(None, "错误", str(e))
        sys.exit(0)
    main()
