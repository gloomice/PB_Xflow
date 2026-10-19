# -*- coding: utf-8 -*-
"""PB X-Flow 主窗口（PyQt6），由 pb_xflow_gui.py 引用。"""
from __future__ import annotations

import codecs
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from configparser import ConfigParser
from datetime import datetime

from PyQt6.QtCore import QEvent, QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QSystemTrayIcon,
    QTabWidget,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

# 从主模块注入 HAS_CTYPES / ctypes API / 常量
import pb_xflow_gui as _root


XFLOW_STYLE = """
    QMainWindow, QWidget#MainWidget { background-color: #1e1e1e; font-family: "Microsoft YaHei UI", "Segoe UI"; }
    QFrame#HeaderFrame { background-color: #252526; border: none; border-bottom: 2px solid #007acc; }
    QFrame#LeftPanel, QFrame#RightPanel { background-color: #252526; border: 1px solid #333; border-radius: 6px; }
    /* 任务页分组：细灰边 */
    QFrame#FlowCardTask {
        background-color: #252526;
        border: 1px solid #3a3d42;
        border-radius: 6px;
    }
    /* 高级页：多块拼成一体，仅最外层细灰框；块之间用顶部分隔线，无间距 */
    QFrame#AdvancedUnifiedPanel {
        background-color: #252526;
        border: 1px solid #3a3d42;
        border-radius: 8px;
    }
    QFrame#FlowAdvSectionFirst {
        background-color: #252526;
        border: none;
    }
    QFrame#FlowAdvSection {
        background-color: #252526;
        border: none;
        border-top: 1px solid #333;
    }
    QScrollArea#AdvancedScroll {
        background-color: #1e1e1e;
        border: none;
    }
    QLabel { color: #e0e0e0; font-weight: bold; font-size: 13px; }
    QLabel#TitleLabel { font-size: 18px; color: #fff; font-weight: 900; }
    QLineEdit { background-color: #1e1e1e; border: 1px solid #3e3e42; border-radius: 4px; color: #d4d4d4; padding: 4px; font-size: 12px; }
    QLineEdit:focus { border: 1px solid #007acc; }
    QPushButton { background-color: #333; border: 1px solid #454545; border-radius: 4px; color: #ccc; padding: 6px; font-weight: bold; }
    QPushButton:hover { background-color: #3e3e3e; color: #fff; }
    QProgressBar { background-color: #1e1e1e; border: 1px solid #3e3e42; border-radius: 4px; text-align: center; }
    QProgressBar::chunk { background-color: #007acc; border-radius: 3px; }
    QPlainTextEdit { background-color: #1e1e1e; color: #4ec9b0; border: 1px solid #3e3e42; border-radius: 4px; font-family: Consolas; font-size: 11px; }
    QMenuBar { background-color: #1e1e1e; border-bottom: 1px solid #333; color: #ccc; }
    QMenuBar::item:selected { background: #333; }
    QMenu { background-color: #252526; color: #ccc; border: 1px solid #444; }
    QMenu::item:selected { background-color: #007acc; color: #fff; }
    QComboBox { background-color: #1e1e1e; border: 1px solid #3e3e42; border-radius: 4px; color: #e0e0e0; padding: 4px; min-width: 80px; }
    QComboBox:hover { border-color: #007acc; }
    QComboBox QAbstractItemView {
        background-color: #252526;
        color: #e8e8e8;
        selection-background-color: #007acc;
        selection-color: #ffffff;
        border: 1px solid #444;
        outline: 0;
        padding: 2px;
    }
    QComboBox QAbstractItemView::item { min-height: 22px; padding: 4px 8px; color: #e8e8e8; }
    QComboBox QAbstractItemView::item:hover { background-color: #3e3e42; color: #fff; }
    QComboBox QAbstractItemView::item:selected { background-color: #007acc; color: #fff; }
    QCheckBox { color: #e0e0e0; font-weight: bold; spacing: 8px; }
    QCheckBox::indicator { width: 16px; height: 16px; border: 1px solid #007acc; border-radius: 3px; background: #1e1e1e; }
    QCheckBox::indicator:hover { border-color: #4da3e6; background: #252526; }
    QCheckBox::indicator:checked { background-color: #007acc; border-color: #007acc; }
    QRadioButton { color: #f0f0f0; font-weight: bold; spacing: 8px; font-size: 13px; }
    QRadioButton::indicator { width: 18px; height: 18px; border: 1px solid #666; border-radius: 9px; background: #1e1e1e; }
    QRadioButton::indicator:hover { border-color: #007acc; }
    QRadioButton::indicator:checked { background-color: #007acc; border-color: #007acc; }
    QTabWidget::pane { border: 1px solid #333; }
    QTabBar::tab { background: #2d2d2d; color: #ccc; padding: 8px 16px; }
    QTabBar::tab:selected { background: #007acc; color: #fff; }
    QMessageBox { background-color: #252526; }
    QMessageBox QLabel { color: #f0f0f0; background-color: transparent; font-size: 13px; }
    QMessageBox QPushButton {
        min-width: 76px;
        padding: 6px 14px;
        background-color: #3e3e42;
        color: #f0f0f0;
        border: 1px solid #555;
        border-radius: 4px;
        font-weight: bold;
    }
    QMessageBox QPushButton:hover { background-color: #505050; border-color: #666; }
    QMessageBox QPushButton:default { border-color: #007acc; background-color: #0e639c; }
"""

PB_XFLOW_APP_STYLESHEET = XFLOW_STYLE


class _ThreadBridge(QObject):
    progress_sig = pyqtSignal(float, float)
    engine_done_sig = pyqtSignal(int, str)
    preflight_done_sig = pyqtSignal(str, object, object)


class PBXFlowWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PB X-Flow")
        self.resize(860, 700)
        self.setMinimumSize(720, 560)
        _ip = _root.get_icon_path()
        if _ip and os.path.isfile(_ip):
            self.setWindowIcon(QIcon(_ip))

        self._bridge = _ThreadBridge()
        self._bridge.progress_sig.connect(self._update_progress_ui)
        self._bridge.engine_done_sig.connect(self._on_engine_finished)
        self._bridge.preflight_done_sig.connect(self._on_preflight_done)

        self.engine_path = _root.find_engine_path()
        self.config_path = _root.get_config_path()
        self.is_running = False
        self.is_paused = False
        self.process = None
        self.read_thread = None
        self.log_queue: queue.Queue = queue.Queue()
        self.failed_files: list = []
        self.task_queue: deque = deque()
        self.active_preset = "C"
        self.last_speed = 0.0
        self.last_progress = 0.0
        self._audit_telemetry_snapshot: tuple[int, int, int, int, int, int] | None = None
        self.engine_start_tick = 0.0
        self.stop_event_handle = None
        self.pause_event_handle = None
        self._telemetry_view = None
        self._telemetry_ptr = None
        self._last_display_progress = 0.0
        self._shm_teardown = False
        self._run_line_pending = None
        self._run_line_timer = QTimer(self)
        self._run_line_timer.setSingleShot(True)
        self._run_line_timer.timeout.connect(self._flush_run_line)
        self._preflight_busy = False
        self._tray_icon: QSystemTrayIcon | None = None

        cw = QWidget()
        cw.setObjectName("MainWidget")
        self.setCentralWidget(cw)
        self._main_layout = QVBoxLayout(cw)
        self._main_layout.setContentsMargins(10, 10, 10, 10)
        self._build_menubar()
        self._build_ui()
        self._load_config()
        if not os.path.exists(self.config_path):
            self._apply_scenario(self.active_preset)
        self._sync_scenario_combo()
        self._update_delete_mode_ui()
        self._check_recovery_session()

        self._log_timer = QTimer(self)
        self._log_timer.timeout.connect(self._drain_log_queue)
        self._log_timer.start(50)

        self._autosave = QTimer(self)
        self._autosave.timeout.connect(self._auto_save_config)
        self._autosave.start(_root.AUTO_SAVE_INTERVAL_MS)

        self._init_tray_icon()

    def _init_tray_icon(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self._tray_icon = QSystemTrayIcon(self)
        _ip = _root.get_icon_path()
        if _ip and os.path.isfile(_ip):
            self._tray_icon.setIcon(QIcon(_ip))
        else:
            self._tray_icon.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))
        m = QMenu()
        m.addAction("显示", self._tray_show_window)
        m.addAction("退出", self._tray_quit_app)
        self._tray_icon.setContextMenu(m)
        self._tray_icon.activated.connect(self._on_tray_activated)
        self._tray_icon.setToolTip("PB X-Flow")
        self._tray_icon.show()

    def _tray_show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _tray_quit_app(self):
        self.close()

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._tray_show_window()

    def changeEvent(self, event: QEvent):
        if (
            event.type() == QEvent.Type.WindowStateChange
            and bool(self.windowState() & Qt.WindowState.WindowMinimized)
            and self._tray_icon
            and self._tray_icon.isVisible()
        ):
            event.ignore()
            self.hide()
            self._tray_icon.showMessage(
                "PB X-Flow",
                "已最小化到系统托盘",
                QSystemTrayIcon.MessageIcon.Information,
                1200,
            )
            return
        super().changeEvent(event)

    # --- menubar ---
    def _build_menubar(self):
        bar = QMenuBar(self)
        tool_m = QMenu("工具", self)
        bar.addMenu(tool_m)
        if sys.platform == "win32" and _root.winreg is not None:
            tool_m.addAction("添加右键菜单", self._on_reg_context_menu)
            tool_m.addAction("删除右键菜单", self._on_unreg_context_menu)
            tool_m.addSeparator()
        tool_m.addAction("查看历史日志…", self._on_open_history_folder)
        about_m = QMenu("关于", self)
        about_m.addAction("使用手册", self._on_open_manual_pdf)
        about_m.addAction("版权信息", self._on_show_copyright_dialog)
        bar.addMenu(about_m)
        self.setMenuBar(bar)

    def _build_ui(self):
        hf = QFrame()
        hf.setObjectName("HeaderFrame")
        hf.setFixedHeight(56)
        hl = QHBoxLayout(hf)
        t = QLabel("PB X-FLOW")
        t.setObjectName("TitleLabel")
        hl.addStretch()
        hl.addWidget(t)
        hl.addStretch()
        self._main_layout.addWidget(hf)

        sp = QSplitter(Qt.Orientation.Horizontal)
        left = QFrame()
        left.setObjectName("LeftPanel")
        ll = QVBoxLayout(left)
        ll.setContentsMargins(8, 8, 8, 8)
        self.tabs = QTabWidget()
        w_task = QWidget()
        w_adv = QWidget()
        w_about = QWidget()
        self.tabs.addTab(w_task, "任务")
        self.tabs.addTab(w_adv, "高级")
        self.tabs.addTab(w_about, "关于")
        ll.addWidget(self.tabs)
        self._build_task_tab(w_task)
        self._build_advanced_tab(w_adv)
        self._build_about_tab(w_about)

        right = QFrame()
        right.setObjectName("RightPanel")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(8, 8, 8, 8)
        self._build_log_panel(rl)

        sp.addWidget(left)
        sp.addWidget(right)
        sp.setStretchFactor(0, 5)
        sp.setStretchFactor(1, 4)
        self._main_layout.addWidget(sp, 1)

        sb = QHBoxLayout()
        self.lbl_engine_status = QLabel("引擎离线 🔴")
        sb.addWidget(self.lbl_engine_status)
        sb.addStretch()
        self._main_layout.addLayout(sb)

    def _card(self, title: str, advanced: bool = False, adv_first: bool = False) -> tuple[QFrame, QGridLayout]:
        card = QFrame()
        if advanced:
            card.setObjectName("FlowAdvSectionFirst" if adv_first else "FlowAdvSection")
        else:
            card.setObjectName("FlowCardTask")
        card.setFrameShape(QFrame.Shape.NoFrame)
        card.setFrameShadow(QFrame.Shadow.Plain)
        v = QVBoxLayout(card)
        v.setContentsMargins(12, 10, 12, 10)
        lt = QLabel(title)
        lt.setStyleSheet("font-weight: bold;")
        v.addWidget(lt)
        grid = QGridLayout()
        v.addLayout(grid)
        return card, grid

    def _build_task_tab(self, parent: QWidget):
        lay = QVBoxLayout(parent)
        lay.setSpacing(8)
        mode_r = QHBoxLayout()
        mode_r.addWidget(QLabel("模式"))
        self.rad_copy = QRadioButton("复制/同步")
        self.rad_delete = QRadioButton("极速销毁")
        self._mode_grp = QButtonGroup(self)
        self._mode_grp.addButton(self.rad_copy)
        self._mode_grp.addButton(self.rad_delete)
        self.rad_copy.setChecked(True)
        self._mode_grp.buttonClicked.connect(self._on_mode_change)
        mode_r.addWidget(self.rad_copy)
        mode_r.addWidget(self.rad_delete)
        mode_r.addStretch()
        lay.addLayout(mode_r)

        def path_row(label: QLabel, attr: str):
            r = QHBoxLayout()
            r.addWidget(label)
            e = QLineEdit()
            e.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            setattr(self, attr, e)
            r.addWidget(e, 1)
            b = QPushButton("浏览")
            b.clicked.connect(lambda _, ent=e: self._browse(ent))
            r.addWidget(b)
            lay.addLayout(r)

        self.lbl_path_src = QLabel("源路径")
        path_row(self.lbl_path_src, "entry_src")
        self.lbl_path_dst = QLabel("目标")
        path_row(self.lbl_path_dst, "entry_dst")

        card, g = self._card("常用")
        lay.addWidget(card)
        r, c = 0, 0
        self.chk_fast = QCheckBox("快速(-F)")
        self.chk_fast.setChecked(True)
        self.chk_ioring = QCheckBox("IoRing(-J)")
        self.chk_ioring.setChecked(True)
        self.chk_mirror = QCheckBox("镜像(-K)")
        self.chk_delta = QCheckBox("增量(-Y)")
        self.chk_defender_exclude = QCheckBox("Defender 排除(-defender-exclude)")
        for w in (self.chk_fast, self.chk_ioring, self.chk_mirror, self.chk_delta):
            g.addWidget(w, r, c)
            c += 1
            if c > 1:
                c = 0
                r += 1
        g.addWidget(self.chk_defender_exclude, r, 0, 1, 2)
        lay.addWidget(card)

        card2, g2 = self._card("校验")
        self.combo_verify = QComboBox()
        self.combo_verify.addItems(["无", "时间", "大小", "MD5", "XXH3"])
        g2.addWidget(self.combo_verify, 0, 0, 1, 2)
        lay.addWidget(card2)

        card3, g3 = self._card("场景预设")
        self.combo_scenario = QComboBox()
        for s in _root.SCENARIOS.values():
            self.combo_scenario.addItem(s["name"])
        self.combo_scenario.currentTextChanged.connect(self._on_scenario_change)
        g3.addWidget(self.combo_scenario, 0, 0, 1, 2)
        lay.addWidget(card3)

        self.btn_start = QPushButton("▶ 开始复制")
        self.btn_start.setObjectName("BtnStart")
        self.btn_start.setMinimumHeight(44)
        self.btn_start.setStyleSheet(
            "QPushButton#BtnStart { background-color: #28a745; color: white; font-size: 15px; font-weight: bold; "
            "border: none; padding: 10px; border-radius: 4px; }"
            "QPushButton#BtnStart:hover { background-color: #218838; }"
        )
        self.btn_start.clicked.connect(self._on_start_clicked)
        lay.addWidget(self.btn_start)
        row = QHBoxLayout()
        self.btn_pause = QPushButton("⏸ 暂停")
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self._on_pause)
        self.btn_stop = QPushButton("■ 停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("background-color: #c0392b; color: white;")
        self.btn_stop.clicked.connect(self._on_stop)
        self.btn_retry = QPushButton("重试")
        self.btn_retry.setEnabled(False)
        self.btn_retry.clicked.connect(self._on_retry)
        self.btn_retry_admin = QPushButton("管理员重试")
        self.btn_retry_admin.setEnabled(False)
        self.btn_retry_admin.clicked.connect(self._on_retry_admin)
        self.chk_queue = QCheckBox("队列")
        for w in (self.btn_pause, self.btn_stop, self.btn_retry, self.btn_retry_admin, self.chk_queue):
            row.addWidget(w)
        row.addStretch()
        lay.addLayout(row)
        lay.addStretch()

    def _build_advanced_tab(self, parent: QWidget):
        scroll = QScrollArea()
        scroll.setObjectName("AdvancedScroll")
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidgetResizable(True)
        inner = QWidget()
        inner.setStyleSheet("background-color: #1e1e1e;")
        outer_wrap = QVBoxLayout(inner)
        outer_wrap.setContentsMargins(0, 0, 0, 0)
        outer_wrap.setSpacing(0)

        shell = QFrame()
        shell.setObjectName("AdvancedUnifiedPanel")
        shell.setFrameShape(QFrame.Shape.NoFrame)
        v = QVBoxLayout(shell)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        outer_wrap.addWidget(shell)

        scroll.setWidget(inner)
        scroll.viewport().setStyleSheet("background-color: #1e1e1e;")
        outer = QVBoxLayout(parent)
        outer.addWidget(scroll)

        adv_first_flag = [True]

        def next_adv_section(title: str) -> tuple[QFrame, QGridLayout]:
            first = adv_first_flag[0]
            adv_first_flag[0] = False
            return self._card(title, advanced=True, adv_first=first)

        def add_rows(title: str, rows: list[tuple[str, str, str, str]]):
            card, g = next_adv_section(title)
            for i, (lbl, attr, ph, val) in enumerate(rows):
                g.addWidget(QLabel(lbl), i, 0)
                e = QLineEdit()
                if ph:
                    e.setPlaceholderText(ph)
                if val:
                    e.setText(val)
                g.addWidget(e, i, 1)
                setattr(self, attr, e)
            v.addWidget(card)

        add_rows(
            "性能参数",
            [
                ("线程", "entry_threads", "64", "64"),
                ("缓冲MB", "entry_buffer", "32", "32"),
                ("限速MB/s", "entry_speed", "0", "0"),
                ("DirectIO阈", "entry_directio", "100", "100"),
                ("IoRing批(-j)", "entry_ioring_batch", "64", "64"),
                ("队列(-Q)", "entry_queue", "30000", "30000"),
                ("大文件QD(-q)", "entry_bigqd", "0", "0"),
            ],
        )

        card, g = next_adv_section("复制选项")
        opts = [
            ("chk_affinity", "Affinity(-W)", True),
            ("chk_vss", "VSS(-V)", False),
            ("chk_flat", "扁平(-i)", False),
            ("chk_move", "移动(-move)", False),
            ("chk_meta", "元数据(-M)", False),
            ("chk_phys", "物理序(-O)", False),
            ("chk_bfs", "BFS(-bfs)", False),
        ]
        r, c = 0, 0
        for attr, text, checked in opts:
            cb = QCheckBox(text)
            cb.setChecked(checked)
            setattr(self, attr, cb)
            g.addWidget(cb, r, c)
            c += 1
            if c > 1:
                c = 0
                r += 1
        v.addWidget(card)

        add_rows(
            "过滤与列表",
            [
                ("过滤(-f)", "entry_filter", "", ""),
                ("列表(-l)", "entry_listfile", "", ""),
                ("任务(-job)", "entry_job", "", ""),
                ("空闲T(-T)", "entry_idle", "64", "64"),
                ("起始日期", "entry_fromdate", "YYYYMMDD", ""),
                ("结束日期", "entry_todate", "YYYYMMDD", ""),
            ],
        )

        card, g = next_adv_section("校验与高级")
        rows_e = [
            ("最小字节", "entry_minsize", "", ""),
            ("最大", "entry_maxsize", "", ""),
            ("开始h(-b)", "entry_starth", "", ""),
            ("结束h(-e)", "entry_endh", "", ""),
            ("时间容差(-G)", "entry_timeallow", "", ""),
        ]
        for i, (lbl, attr, ph, val) in enumerate(rows_e):
            g.addWidget(QLabel(lbl), i, 0)
            e = QLineEdit()
            if ph:
                e.setPlaceholderText(ph)
            if val:
                e.setText(val)
            g.addWidget(e, i, 1)
            setattr(self, attr, e)
        cb_fr = QFrame()
        cb_fr.setFrameShape(QFrame.Shape.NoFrame)
        cb_fr.setFrameShadow(QFrame.Shadow.Plain)
        cb_fr.setStyleSheet("QFrame { background-color: transparent; border: none; }")
        cbl = QGridLayout(cb_fr)
        adv_checks = [
            ("chk_acl", "ACL(-A)"),
            ("chk_sample", "抽样(-S)"),
            ("chk_case", "忽略大小写(-c)"),
            ("chk_high", "高优(-H)"),
            ("chk_lowio", "低IO(-U)"),
            ("chk_perfect", "全量校验"),
            ("chk_norename", "不重命名"),
            ("chk_verifyinfo", "校验详情"),
            ("chk_zeroskip", "零块跳过"),
        ]
        rr, cc = 0, 0
        for attr, tx in adv_checks:
            cb = QCheckBox(tx)
            setattr(self, attr, cb)
            cbl.addWidget(cb, rr, cc)
            cc += 1
            if cc > 1:
                cc = 0
                rr += 1
        g.addWidget(cb_fr, len(rows_e), 0, 1, 2)
        v.addWidget(card)

        card, g = next_adv_section("抽样与企业")
        for i, (lbl, attr, ph, val) in enumerate(
            [
                ("抽样阈值GB", "entry_sample_thresh", "5", "5"),
                ("中间块", "entry_sample_random", "6", "6"),
                ("IPG ms", "entry_ipg", "0", "0"),
            ]
        ):
            g.addWidget(QLabel(lbl), i, 0)
            e = QLineEdit()
            e.setPlaceholderText(ph)
            e.setText(val)
            g.addWidget(e, i, 1)
            setattr(self, attr, e)
        cb5 = QFrame()
        cb5.setFrameShape(QFrame.Shape.NoFrame)
        cb5.setFrameShadow(QFrame.Shadow.Plain)
        cb5.setStyleSheet("QFrame { background-color: transparent; border: none; }")
        g5 = QGridLayout(cb5)
        for i, (attr, tx) in enumerate(
            [
                ("chk_copyall", "全量(-copyall)"),
                ("chk_rh_strict", "严格(-rh_strict)"),
                ("chk_hard_ws", "强内存(-hard_ws)"),
                ("chk_host_aware", "负载感知(-host_aware)"),
            ]
        ):
            cb = QCheckBox(tx)
            setattr(self, attr, cb)
            g5.addWidget(cb, i // 2, i % 2)
        g.addWidget(cb5, 3, 0, 1, 2)
        v.addWidget(card)

        card, g = next_adv_section("MFT 与续传")
        self.chk_mft_scan = QCheckBox("MFT扫描(-mft_scan)")
        self.chk_mft_raw = QCheckBox("Raw MFT(-mft_raw)")
        g.addWidget(self.chk_mft_scan, 0, 0, 1, 2)
        g.addWidget(self.chk_mft_raw, 1, 0, 1, 2)
        g.addWidget(QLabel("续传间隔s"), 2, 0)
        self.entry_checkpoint_interval = QLineEdit("300")
        g.addWidget(self.entry_checkpoint_interval, 2, 1)
        g.addWidget(QLabel("续传GB"), 3, 0)
        self.entry_checkpoint_gb = QLineEdit("100")
        g.addWidget(self.entry_checkpoint_gb, 3, 1)
        v.addWidget(card)
        v.addStretch()

    def _build_about_tab(self, parent: QWidget):
        v = QVBoxLayout(parent)
        v.addWidget(QLabel("PB X-Flow Ver123"))
        v.addWidget(QLabel("Copyright © 2025-2026 Wuhan Linkleading"))
        v.addWidget(QLabel("顶部菜单：工具 · 关于"))
        for tx, fn in [
            ("帮助（参数说明）", self._on_help),
            ("使用手册 (PDF)", self._on_open_manual_pdf),
            ("版权信息", self._on_show_copyright_dialog),
            ("关于", self._on_about),
            ("Defender 排除", self._on_defender),
        ]:
            b = QPushButton(tx)
            b.setFixedWidth(220)
            b.clicked.connect(fn)
            v.addWidget(b, alignment=Qt.AlignmentFlag.AlignHCenter)
        v.addStretch()

    def _build_log_panel(self, lay: QVBoxLayout):
        top = QHBoxLayout()
        top.addWidget(QLabel("任务完成后"))
        self.combo_post = QComboBox()
        self.combo_post.addItems(["无操作", "自动关机"])
        top.addWidget(self.combo_post)
        self.btn_preflight = QPushButton("预检")
        self.btn_preflight.clicked.connect(self._on_preflight)
        top.addWidget(self.btn_preflight)
        top.addStretch()
        lay.addLayout(top)

        self.lbl_telemetry = QLabel("速度: -- MB/s | 进度: --% | ETA: --")
        self.lbl_telemetry.setStyleSheet("font-family: Consolas; font-size: 14px; font-weight: bold; padding: 10px;")
        sf = QFrame()
        sf.setStyleSheet("background-color: #2b2b2b; border-radius: 6px;")
        sl = QVBoxLayout(sf)
        sl.addWidget(self.lbl_telemetry)
        lay.addWidget(sf)

        self.progress = QProgressBar()
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        lay.addWidget(self.progress)

        lay.addWidget(QLabel("实时日志"))
        self.log_text = QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumBlockCount(_root.MAX_LOG_LINES)
        lay.addWidget(self.log_text, 1)

    # --- helpers ---
    def _mode_is_delete(self) -> bool:
        return self.rad_delete.isChecked()

    def _on_mode_change(self):
        self._update_delete_mode_ui()

    def _update_delete_mode_ui(self):
        del_ = self._mode_is_delete()
        self.entry_src.setEnabled(not del_)
        self.entry_dst.setEnabled(True)
        if del_:
            self.lbl_path_src.setText("源路径（复制模式）")
            self.lbl_path_dst.setText("待销毁目录")
            self.entry_src.setPlaceholderText("销毁模式不使用此栏")
            self.entry_dst.setPlaceholderText("填写要销毁的根目录，请再三确认")
        else:
            self.lbl_path_src.setText("源路径")
            self.lbl_path_dst.setText("目标")
            self.entry_src.setPlaceholderText("")
            self.entry_dst.setPlaceholderText("")
        for w in (
            self.chk_delta,
            self.chk_mirror,
            self.chk_move,
            self.chk_copyall,
            self.chk_rh_strict,
            self.chk_perfect,
            self.chk_norename,
            self.chk_verifyinfo,
            self.chk_zeroskip,
            self.chk_defender_exclude,
            self.entry_checkpoint_interval,
            self.entry_checkpoint_gb,
        ):
            if w is not None:
                w.setEnabled(not del_)
        self._set_primary_button_running(self.is_running)

    def _browse(self, entry: QLineEdit):
        d = QFileDialog.getExistingDirectory(self, "选择目录")
        if d:
            entry.setText(d)

    def _get_scenario_key_from_name(self, name: str) -> str:
        for k, v in _root.SCENARIOS.items():
            if v["name"] == name:
                return k
        return "C"

    def _on_scenario_change(self, selected_name: str):
        self._apply_scenario(self._get_scenario_key_from_name(selected_name))

    def _apply_scenario(self, key: str):
        sc = _root.SCENARIOS.get(key, _root.SCENARIOS["C"])
        entries = sc.get("entries", {})
        checks = sc.get("checks", {})
        default_entries = {
            "threads": "64",
            "buffer": "32",
            "speed": "0",
            "directio": "100",
            "ioring_batch": "256",
            "queue": "30000",
            "bigqd": "0",
            "checkpoint_interval": "300",
            "checkpoint_gb": "100",
            "starth": "",
            "endh": "",
            "idle": "64",
        }
        merged = {**default_entries, **entries}
        for k, v in merged.items():
            e = getattr(self, f"entry_{k}", None)
            if e is not None:
                e.setText(str(v))
        all_checks = [
            "fast",
            "ioring",
            "affinity",
            "mirror",
            "delta",
            "vss",
            "flat",
            "bfs",
            "mft_scan",
            "mft_raw",
            "host_aware",
            "lowio",
            "perfect",
            "verifyinfo",
            "acl",
            "rh_strict",
            "copyall",
        ]
        for ck in all_checks:
            w = getattr(self, f"chk_{ck}", None)
            if w is not None:
                w.setChecked(bool(checks.get(ck, ck in ("fast", "ioring", "affinity"))))
        if "verify" in sc:
            self.combo_verify.setCurrentText(sc["verify"])
        if sc.get("mode") == "delete":
            self.rad_delete.setChecked(True)
        else:
            self.rad_copy.setChecked(True)
        self.active_preset = key
        self._update_delete_mode_ui()

    def _sync_scenario_combo(self):
        name = _root.SCENARIOS.get(self.active_preset, _root.SCENARIOS["C"])["name"]
        self.combo_scenario.blockSignals(True)
        self.combo_scenario.setCurrentText(name)
        self.combo_scenario.blockSignals(False)

    def _build_command_line(self, is_retry=False, list_path=None):
        src = self.entry_src.text().strip().replace("/", "\\")
        dst = self.entry_dst.text().strip().replace("/", "\\")
        is_delete = self._mode_is_delete()
        if is_delete:
            if not dst:
                return None, None, "待销毁目录（目标路径）不能为空！"
        else:
            if not src:
                return None, None, "源路径不能为空！"
            if not dst:
                return None, None, "目标路径不能为空！"
            src_cmp = os.path.normcase(os.path.normpath(src)).rstrip("\\/")
            dst_cmp = os.path.normcase(os.path.normpath(dst)).rstrip("\\/")
            if src_cmp and dst_cmp and src_cmp == dst_cmp:
                return None, None, "源路径与目标路径不能相同！"

        pid = os.getpid()
        if _root.HAS_CTYPES:
            pid = _root.GetCurrentProcessId()
        exe = self.engine_path
        pid_str = str(pid)
        if is_delete:
            # 引擎 -delete 仅识别 -s <path>；约定：GUI「待销毁目录」= 目标框，避免误删源数据盘
            del_root = dst
            del_esc = _root.escape_path_for_cmd(del_root)
            parts = [f'"{exe}"', "-s", f'"{del_esc}"']
            args = [exe, "-s", del_root]
            parts.extend(["-delete", "-R", "-z", "-P", pid_str])
            args.extend(["-delete", "-R", "-z", "-P", pid_str])
        else:
            src_esc = _root.escape_path_for_cmd(src)
            dst_esc = _root.escape_path_for_cmd(dst)
            parts = [f'"{exe}"', "-s", f'"{src_esc}"']
            args = [exe, "-s", src]
            parts.extend(["-d", f'"{dst_esc}"', "-R", "-z", "-P", pid_str])
            args.extend(["-d", dst, "-R", "-z", "-P", pid_str])
            if is_retry and list_path:
                parts.extend(["-l", f'"{_root.escape_path_for_cmd(list_path)}"'])
                args.extend(["-l", list_path])

        def add(*a):
            parts.extend(a)
            args.extend(a)

        if not is_delete and self.chk_defender_exclude.isChecked():
            add("-defender-exclude")
        if self.chk_fast.isChecked():
            add("-F")
        if self.chk_ioring.isChecked():
            add("-J")
        if self.chk_affinity.isChecked():
            add("-W")
        if self.chk_vss.isChecked():
            add("-V")
        if self.chk_flat.isChecked():
            add("-i")
        if self.chk_meta.isChecked():
            add("-M")
        if not is_delete:
            if self.chk_mirror.isChecked():
                add("-K")
            if self.chk_move.isChecked():
                add("-move")
        if self.chk_phys.isChecked():
            add("-O")
        if self.chk_bfs.isChecked():
            add("-bfs")
        if self.chk_mft_scan.isChecked():
            add("-mft_scan")
        if self.chk_mft_raw.isChecked():
            add("-mft_raw")
        if not is_delete:
            if is_retry and not list_path:
                add("-Y")
            elif not is_retry and self.chk_delta.isChecked():
                add("-Y")
        add("-I", "100")
        directio = self.entry_directio.text().strip()
        if directio and directio.isdigit() and int(directio) > 0:
            add("-directio_threshold=" + directio)
        speed = self.entry_speed.text().strip()
        if speed and speed.isdigit() and int(speed) > 0:
            add("-L", speed)
        if not is_delete:
            verify_map = {"无": None, "时间": "mtime", "大小": "size", "MD5": "md5", "XXH3": "xxh3"}
            v = verify_map.get(self.combo_verify.currentText(), None)
            if v == "mtime":
                add("-m")
            elif v == "size":
                add("-C")
            elif v == "md5":
                add("-D")
            elif v == "xxh3":
                add("-X")
        t = self.entry_threads.text().strip()
        if t:
            add("-t", t)
        b = self.entry_buffer.text().strip()
        if b:
            add("-B", b)
        if not is_retry:
            f = self.entry_filter.text().strip()
            if f:
                parts.extend(["-f", f'"{_root.escape_path_for_cmd(f)}"'])
                args.extend(["-f", f])
            lf = self.entry_listfile.text().strip()
            if lf:
                parts.extend(["-l", f'"{_root.escape_path_for_cmd(lf)}"'])
                args.extend(["-l", lf])
            j = self.entry_job.text().strip()
            if j:
                add("-job=" + j)
        idle = self.entry_idle.text().strip()
        if idle and idle.isdigit() and int(idle) > 0:
            add("-T", idle)
        jb = self.entry_ioring_batch.text().strip()
        if jb and jb.isdigit() and int(jb) > 0:
            add("-j", jb)
        q = self.entry_queue.text().strip()
        if q and q.isdigit() and int(q) > 0:
            add("-Q", q)
        bq = self.entry_bigqd.text().strip()
        if bq and bq.isdigit() and int(bq) > 0:
            add("-q", bq)
        if not is_retry:
            fd = self.entry_fromdate.text().strip()
            if fd:
                add("-from_date=" + fd)
            td = self.entry_todate.text().strip()
            if td:
                add("-to_date=" + td)
            ms = self.entry_minsize.text().strip()
            if ms and ms.isdigit() and int(ms) > 0:
                add("-min_size=" + ms)
            mx = self.entry_maxsize.text().strip()
            if mx and mx.isdigit() and int(mx) > 0:
                add("-max_size=" + mx)
            sh = self.entry_starth.text().strip()
            if sh and sh.isdigit() and 0 <= int(sh) <= 23:
                add("-b", sh)
            eh = self.entry_endh.text().strip()
            if eh and eh.isdigit() and 0 <= int(eh) <= 23:
                add("-e", eh)
            if self.chk_rh_strict.isChecked():
                add("-rh_strict")
            ta = self.entry_timeallow.text().strip()
            if ta and ta.isdigit() and int(ta) > 0:
                add("-G", ta)
        ipg = self.entry_ipg.text().strip()
        if ipg and ipg.isdigit() and int(ipg) > 0:
            add("-ipg=" + ipg)
        if self.chk_acl.isChecked():
            add("-A")
        if self.chk_copyall.isChecked():
            add("-copyall")
        if self.chk_sample.isChecked():
            add("-S")
        st = self.entry_sample_thresh.text().strip()
        if st and st.isdigit() and int(st) > 0:
            add("-sample_threshold=" + st)
        sr = self.entry_sample_random.text().strip()
        if sr and sr.isdigit() and int(sr) > 0:
            add("-sample_random=" + sr)
        if self.chk_case.isChecked():
            add("-c")
        if self.chk_high.isChecked():
            add("-H")
        if self.chk_lowio.isChecked():
            add("-U")
        if self.chk_hard_ws.isChecked():
            add("-hard_ws")
        if self.chk_host_aware.isChecked():
            add("-host_aware")
        if not is_delete:
            if self.chk_perfect.isChecked():
                add("-perfect_verify")
            if self.chk_norename.isChecked():
                add("-no_verify_rename")
            if self.chk_verifyinfo.isChecked():
                add("-verifyinfo")
            if self.chk_zeroskip.isChecked():
                add("-zero-skip")
        ci = self.entry_checkpoint_interval.text().strip()
        if ci and ci.isdigit() and int(ci) > 0 and int(ci) != 300:
            add("-checkpoint_interval=" + ci)
        cg = self.entry_checkpoint_gb.text().strip()
        if cg and cg.isdigit() and int(cg) > 0 and int(cg) != 100:
            add("-checkpoint_gb=" + cg)
        return " ".join(parts), args, None

    def _save_config(self):
        cfg = ConfigParser()
        cfg["UI"] = {
            "Src": self.entry_src.text(),
            "Dst": self.entry_dst.text(),
            "Threads": self.entry_threads.text() or "64",
            "Buffer": self.entry_buffer.text() or "32",
            "Fast": "1" if self.chk_fast.isChecked() else "0",
            "IoRing": "1" if self.chk_ioring.isChecked() else "0",
            "Affinity": "1" if self.chk_affinity.isChecked() else "0",
            "Preset": str(self.active_preset),
            "PostAction": "1" if self.combo_post.currentText() == "自动关机" else "0",
            "SpeedLimit": self.entry_speed.text() or "0",
            "DeleteMode": "1" if self._mode_is_delete() else "0",
            "QueueMode": "1" if self.chk_queue.isChecked() else "0",
            "Verify": self.combo_verify.currentText(),
            "DefenderExclude": "1" if self.chk_defender_exclude.isChecked() else "0",
        }
        adv = {}
        for name in (
            "mirror",
            "delta",
            "vss",
            "flat",
            "move",
            "meta",
            "phys",
            "bfs",
            "mft_scan",
            "mft_raw",
            "acl",
            "sample",
            "case",
            "high",
            "lowio",
            "perfect",
            "norename",
            "verifyinfo",
            "zeroskip",
            "copyall",
            "rh_strict",
            "hard_ws",
            "host_aware",
        ):
            c = getattr(self, f"chk_{name}", None)
            if c is not None:
                adv[name] = "1" if c.isChecked() else "0"
        for key in (
            "directio",
            "filter",
            "listfile",
            "job",
            "idle",
            "fromdate",
            "todate",
            "minsize",
            "maxsize",
            "starth",
            "endh",
            "timeallow",
            "ipg",
            "sample_thresh",
            "sample_random",
            "checkpoint_interval",
            "checkpoint_gb",
        ):
            e = getattr(self, f"entry_{key}", None)
            if e is not None:
                adv[key] = e.text()
        cfg["Advanced"] = adv
        with open(self.config_path, "w", encoding="utf-8") as f:
            cfg.write(f)

    def _load_config(self):
        if not os.path.exists(self.config_path):
            return
        try:
            cfg = ConfigParser()
            cfg.read(self.config_path, encoding="utf-8")
            if "UI" in cfg:
                u = cfg["UI"]
                self.entry_src.setText(u.get("Src", ""))
                self.entry_dst.setText(u.get("Dst", ""))
                self.entry_threads.setText(u.get("Threads", "64"))
                self.entry_buffer.setText(u.get("Buffer", "32"))
                self.chk_fast.setChecked(u.get("Fast", "1") == "1")
                self.chk_ioring.setChecked(u.get("IoRing", "1") == "1")
                if u.get("DeleteMode", "0") == "1":
                    self.rad_delete.setChecked(True)
                else:
                    self.rad_copy.setChecked(True)
                self.chk_queue.setChecked(u.get("QueueMode", "0") == "1")
                self.combo_post.setCurrentText("自动关机" if u.get("PostAction", "0") == "1" else "无操作")
                p = u.get("Preset", "C")
                legacy = {"1": "B", "2": "C", "3": "A"}
                self.active_preset = legacy.get(str(p), p) if p in ("1", "2", "3") else (p or "C")
                self._apply_scenario(self.active_preset)
                self._sync_scenario_combo()
                if u.get("Verify"):
                    self.combo_verify.setCurrentText(u.get("Verify", "无"))
                self.chk_defender_exclude.setChecked(u.get("DefenderExclude", "0") == "1")
            if "Advanced" in cfg:
                a = cfg["Advanced"]
                for name in (
                    "mirror",
                    "delta",
                    "vss",
                    "flat",
                    "move",
                    "meta",
                    "phys",
                    "bfs",
                    "mft_scan",
                    "mft_raw",
                    "acl",
                    "sample",
                    "case",
                    "high",
                    "lowio",
                    "perfect",
                    "norename",
                    "verifyinfo",
                    "zeroskip",
                    "copyall",
                    "rh_strict",
                    "hard_ws",
                    "host_aware",
                ):
                    c = getattr(self, f"chk_{name}", None)
                    if c is not None and name in a:
                        c.setChecked(a[name] == "1")
                for key in (
                    "directio",
                    "filter",
                    "listfile",
                    "job",
                    "idle",
                    "fromdate",
                    "todate",
                    "minsize",
                    "maxsize",
                    "starth",
                    "endh",
                    "timeallow",
                    "ipg",
                    "sample_thresh",
                    "sample_random",
                    "checkpoint_interval",
                    "checkpoint_gb",
                ):
                    e = getattr(self, f"entry_{key}", None)
                    if e is not None and key in a:
                        e.setText(a[key])
        except Exception:
            pass

    def _auto_save_config(self):
        if not self.is_running:
            self._save_config()

    def _check_recovery_session(self):
        session_path = os.path.join(os.path.dirname(self.config_path), "session.dat")
        if os.path.exists(session_path):
            try:
                os.remove(session_path)
            except OSError:
                pass

    def _append_log(self, text: str, is_error: bool = False):
        self.log_queue.put((text, is_error))

    def _drain_log_queue(self):
        batch = []
        try:
            batch.append(self.log_queue.get_nowait())
            while len(batch) < 20:
                batch.append(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        for text, is_err in batch:
            self._do_append_log(text, is_err)

    def _do_append_log(self, text: str, is_error: bool = False):
        if not text:
            return
        display = text.replace("\r", "\n").strip()
        if not display:
            return
        prog_tags = ("[RUN]", "[File]", "[Dirs]", "PROGRESS:")
        if any(tag in display for tag in prog_tags):
            lines = display.split("\n")
            normal_lines = []
            last_prog = ""
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                found = None
                for tag in prog_tags:
                    if tag in line:
                        found = tag
                        break
                if found:
                    idx = line.find(found)
                    if idx > 0:
                        normal_lines.append(line[:idx].strip())
                    last_prog = line[idx:].strip()
                else:
                    normal_lines.append(line)
            if normal_lines:
                self._raw_insert_log("\n".join(normal_lines) + "\n", is_error)
            if last_prog:
                self._schedule_run_status_line(last_prog)
            return
        if not display.endswith("\n"):
            display += "\n"
        self._raw_insert_log(display, is_error)

    def _raw_insert_log(self, display: str, is_error: bool):
        cur = self.log_text.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("#e74c3c" if is_error else "#4ec9b0"))
        cur.mergeCharFormat(fmt)
        cur.insertText(display)
        self.log_text.setTextCursor(cur)
        sb = self.log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _schedule_run_status_line(self, text: str):
        s = text.replace("\r", "").strip() if text else ""
        if not s:
            return
        if not s.endswith("\n"):
            s += "\n"
        self._run_line_pending = s
        self._run_line_timer.stop()
        self._run_line_timer.start(8)

    def _flush_run_line(self):
        pending = self._run_line_pending
        if pending:
            self._do_replace_run_status_line(pending)

    def _do_replace_run_status_line(self, text: str):
        display = text.strip()
        if not display:
            return
        display += "\n"
        markers = ("[RUN]", "[File]", "[Dirs]", "PROGRESS:")
        lines = self.log_text.toPlainText().split("\n")
        while lines and any(m in lines[-1] for m in markers):
            lines.pop()
        body = "\n".join(lines)
        if body and not body.endswith("\n"):
            body += "\n"
        self.log_text.setPlainText(body + display)
        sb = self.log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_start_clicked(self):
        if self.is_running:
            self._on_stop()
            return
        self._on_start()

    def _on_start(self):
        if self.is_running:
            return
        self._save_config()
        use_queue = self.chk_queue.isChecked()
        if use_queue:
            src = self.entry_src.text().strip()
            dst = self.entry_dst.text().strip()
            if self._mode_is_delete():
                if dst:
                    self.task_queue.append({"src": "", "dst": dst, "is_delete": True})
            elif src:
                self.task_queue.append({"src": src, "dst": dst, "is_delete": False})
        if use_queue and self.task_queue:
            qt = self.task_queue.popleft()
            self.entry_src.setText(qt["src"])
            self.entry_dst.setText(qt["dst"])
            if qt["is_delete"]:
                self.rad_delete.setChecked(True)
            else:
                self.rad_copy.setChecked(True)
            self._update_delete_mode_ui()
        self._start_engine()

    def _start_engine(self, custom_cmd=None, custom_args=None):
        if self.is_running:
            return
        self.is_running = True
        self.failed_files.clear()
        self.engine_start_tick = time.time()
        self._last_display_progress = 0.0
        self._audit_telemetry_snapshot = None
        self._shm_teardown = False
        self._run_line_timer.stop()
        self._run_line_pending = None

        cmd, args, err = self._build_command_line()
        if err and not custom_cmd:
            self.is_running = False
            self._message(err, "错误")
            return
        if custom_cmd is not None:
            cmd = custom_cmd
            args = custom_args

        is_delete = self._mode_is_delete()
        if not custom_cmd and is_delete:
            del_path = self.entry_dst.text().strip()
            if (
                QMessageBox.question(
                    self,
                    "极速销毁 — 请确认",
                    "即将永久销毁以下目录中的全部内容（不可恢复）：\n\n"
                    f"{del_path}\n\n"
                    "请确认这是您要清理的目标路径，而非数据源。是否继续？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                self.is_running = False
                return

        work_dir = os.path.dirname(self.engine_path) or "."
        resume_path = os.path.join(work_dir, "pb_xflow_resume.dat")
        if not is_delete and os.path.exists(resume_path) and not custom_cmd:
            if (
                QMessageBox.question(
                    self,
                    "断点续传",
                    "发现上次意外中断的会话。是否以断点续传模式继续？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                cmd += " -resume"
                if args is not None:
                    args.append("-resume")
                if not self.chk_delta.isChecked():
                    cmd += " -Y"
                    if args is not None:
                        args.append("-Y")

        if _root.HAS_CTYPES:
            pid = _root.GetCurrentProcessId()
            self.stop_event_handle = _root.CreateEventW(None, True, False, _root.TELEMETRY_STOP_EVENT + str(pid))
            self.pause_event_handle = _root.CreateEventW(None, True, False, _root.TELEMETRY_PAUSE_RELEASE + str(pid))

        self._set_primary_button_running(True)
        self.lbl_engine_status.setText("引擎运行中 🟢")
        self.btn_pause.setEnabled(True)
        self.btn_stop.setEnabled(True)
        self.progress.setValue(0)
        self.lbl_telemetry.setText("速度: -- MB/s | 进度: --% | ETA: --")

        self.log_text.clear()
        if is_delete:
            self._append_log("--- [极速销毁模式] ---\r\n")
        self._append_log("--- [PB Turbo Engine] ---\r\n运行参数: ")
        self._append_log(cmd + "\r\n\r\n")

        self._telemetry_view = None
        self._telemetry_ptr = None
        shm_handles = []
        log_ring_meta = log_ring_buf = log_ring_event_handle = None
        if _root.HAS_CTYPES and sys.platform == "win32" and args and "-P" in args:
            pid = _root.GetCurrentProcessId()
            try:
                prefix = _root.TELEMETRY_SHM_PREFIX + str(pid)

                def valid_handle(h):
                    return h and h not in (0, _root.INVALID_HANDLE_VALUE, -1)

                h1 = _root.CreateFileMappingW(
                    _root.INVALID_HANDLE_VALUE, None, _root.PAGE_READWRITE, 0, _root.TELEMETRY_SHM_BYTES, prefix
                )
                if valid_handle(h1):
                    shm_handles.append(("telemetry", h1))
                    tv = _root.MapViewOfFile(h1, _root.FILE_MAP_READ | _root.FILE_MAP_WRITE, 0, 0, _root.TELEMETRY_SHM_BYTES)
                    if tv:
                        self._telemetry_view = tv
                        self._telemetry_ptr = _root.ctypes.cast(tv, _root.ctypes.POINTER(_root.SharedTelemetry))
                buf_name = prefix + _root.LOG_RING_BUF_SUFFIX
                h2 = _root.CreateFileMappingW(
                    _root.INVALID_HANDLE_VALUE, None, _root.PAGE_READWRITE, 0, _root.LOG_RING_SIZE, buf_name
                )
                if valid_handle(h2):
                    shm_handles.append(("buf", h2))
                    log_ring_buf = _root.MapViewOfFile(h2, _root.FILE_MAP_READ | _root.FILE_MAP_WRITE, 0, 0, _root.LOG_RING_SIZE)
                meta_name = prefix + _root.LOG_RING_SHM_SUFFIX
                h3 = _root.CreateFileMappingW(
                    _root.INVALID_HANDLE_VALUE,
                    None,
                    _root.PAGE_READWRITE,
                    0,
                    _root.SHARED_LOG_RING_META_SIZE,
                    meta_name,
                )
                if valid_handle(h3):
                    shm_handles.append(("meta", h3))
                    log_ring_meta = _root.MapViewOfFile(
                        h3, _root.FILE_MAP_READ | _root.FILE_MAP_WRITE, 0, 0, _root.SHARED_LOG_RING_META_SIZE
                    )
                if log_ring_meta and log_ring_buf:
                    ev_name = _root.LOG_RING_EVENT_PREFIX + str(pid)
                    h_evt = _root.CreateEventW(None, True, False, ev_name)
                    if valid_handle(h_evt):
                        log_ring_event_handle = h_evt
                        shm_handles.append(("log_ring_evt", h_evt))
            except Exception:
                pass

        win = self

        def run():
            import ctypes

            log_ring_thread = None
            try:
                create_flags = 0
                startupinfo = None
                if sys.platform == "win32":
                    create_flags = subprocess.CREATE_NO_WINDOW
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    startupinfo.wShowWindow = subprocess.SW_HIDE
                win.process = subprocess.Popen(
                    args if args else cmd,
                    shell=(args is None),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    cwd=work_dir,
                    creationflags=create_flags,
                    startupinfo=startupinfo,
                    bufsize=0,
                )

                def log_ring_reader():
                    if not log_ring_meta or not log_ring_buf:
                        return

                    def to_addr(p):
                        return int(ctypes.cast(p, ctypes.c_void_p).value) if p else 0

                    meta_addr = to_addr(log_ring_meta)
                    buf_addr = to_addr(log_ring_buf)
                    engine_head = ctypes.c_uint32.from_address(meta_addr)
                    gui_tail = ctypes.c_uint32.from_address(meta_addr + 64)
                    buf_arr = (ctypes.c_uint8 * _root.LOG_RING_SIZE).from_address(buf_addr)

                    def read_buf(off, n):
                        return bytes(buf_arr[(off + i) % _root.LOG_RING_SIZE] for i in range(n))

                    evt = log_ring_event_handle
                    wait_ms = 500
                    while win.is_running and win.process and not getattr(win, "_shm_teardown", False):
                        if evt and _root.HAS_CTYPES:
                            w = _root.WaitForSingleObject(evt, wait_ms)
                            if not win.is_running or not win.process or getattr(win, "_shm_teardown", False):
                                break
                            if w == _root.WAIT_FAILED:
                                break
                            if w == _root.WAIT_OBJECT_0:
                                _root.ResetEvent(evt)
                        else:
                            if getattr(win, "_shm_teardown", False):
                                break
                            if engine_head.value == gui_tail.value:
                                time.sleep(0.05)
                                continue
                        while True:
                            if getattr(win, "_shm_teardown", False):
                                break
                            while True:
                                if getattr(win, "_shm_teardown", False):
                                    break
                                eng_h = engine_head.value
                                gui_t = gui_tail.value
                                if gui_t == eng_h:
                                    break
                                size = int.from_bytes(read_buf(gui_t, 4), "little")
                                if size < 6 or size > 2056:
                                    gui_tail.value = (gui_t + 4) % _root.LOG_RING_SIZE
                                    continue
                                data_bytes = read_buf(gui_t + 6, size - 6)
                                try:
                                    line = data_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
                                    if not line.strip():
                                        gui_tail.value = (gui_t + size) % _root.LOG_RING_SIZE
                                        continue
                                    prog_tags = ("[RUN]", "[File]", "[Dirs]", "PROGRESS:")
                                    if any(tag in line for tag in prog_tags):
                                        prog, speed = _root.parse_progress_speed(line)
                                        if prog > 0 or speed > 0:
                                            win._bridge.progress_sig.emit(prog, speed)
                                        win._append_log(line, False)
                                        gui_tail.value = (gui_t + size) % _root.LOG_RING_SIZE
                                        continue
                                    is_err = _root.is_error_line(line)
                                    if is_err:
                                        win.failed_files.append(line)
                                    win._append_log(line.strip() + "\n", is_err)
                                    prog, speed = _root.parse_progress_speed(line)
                                    if prog > 0 or speed > 0:
                                        win._bridge.progress_sig.emit(prog, speed)
                                except Exception:
                                    pass
                                gui_tail.value = (gui_t + size) % _root.LOG_RING_SIZE
                            if getattr(win, "_shm_teardown", False):
                                break
                            eng_h = engine_head.value
                            gui_t = gui_tail.value
                            if gui_t != eng_h:
                                continue
                            break

                if log_ring_meta and log_ring_buf:
                    log_ring_thread = threading.Thread(target=log_ring_reader, daemon=True)
                    log_ring_thread.start()

                decoder = codecs.getincrementaldecoder(_root.ENGINE_STDOUT_ENCODING)(errors="replace")
                buf = ""
                while win.is_running:
                    raw = win.process.stdout.read(4096)
                    if not raw:
                        break
                    buf += decoder.decode(raw)
                    while "\n" in buf or "\r" in buf:
                        idx = min(
                            buf.index("\n") if "\n" in buf else len(buf),
                            buf.index("\r") if "\r" in buf else len(buf),
                        )
                        raw_line = buf[:idx]
                        buf = buf[idx + 1 :]
                        while buf and buf[0] in "\r\n":
                            buf = buf[1:]
                        line = raw_line.strip()
                        if not line:
                            continue
                        prog_tags = ("[RUN]", "[File]", "[Dirs]", "PROGRESS:")
                        if any(tag in line for tag in prog_tags):
                            prog, speed = _root.parse_progress_speed(line)
                            if prog > 0 or speed > 0:
                                win._bridge.progress_sig.emit(prog, speed)
                            win._append_log(line, False)
                            continue
                        is_err = _root.is_error_line(line)
                        if is_err:
                            win.failed_files.append(line)
                        win._append_log(line + "\n", is_err)
                        prog, speed = _root.parse_progress_speed(line)
                        if prog > 0 or speed > 0:
                            win._bridge.progress_sig.emit(prog, speed)
                buf += decoder.decode(b"", final=True)
                if buf.strip():
                    for line in buf.replace("\r", "\n").split("\n"):
                        clean = line.strip()
                        prog_tags = ("[RUN]", "[File]", "[Dirs]", "PROGRESS:")
                        if not clean or any(tag in clean for tag in prog_tags):
                            continue
                        is_err = _root.is_error_line(clean)
                        if is_err:
                            win.failed_files.append(clean)
                        win._append_log(clean + "\n", is_err)
                win.process.wait()
                exit_code = win.process.returncode
                win._bridge.engine_done_sig.emit(exit_code, "")
            except Exception as e:
                win._bridge.engine_done_sig.emit(-1, str(e))
            finally:
                win._shm_teardown = True
                win.process = None
                if log_ring_thread is not None:
                    log_ring_thread.join(timeout=5.0)
                time.sleep(0.05)
                if log_ring_meta:
                    try:
                        _root.UnmapViewOfFile(log_ring_meta)
                    except Exception:
                        pass
                if log_ring_buf:
                    try:
                        _root.UnmapViewOfFile(log_ring_buf)
                    except Exception:
                        pass
                win._audit_telemetry_snapshot = None
                if getattr(win, "_telemetry_ptr", None) and _root.HAS_CTYPES:
                    try:
                        d = win._telemetry_ptr.contents.data
                        if int(d.magic) == int(_root.TELEMETRY_MAGIC):
                            win._audit_telemetry_snapshot = (
                                int(d.totalBytes),
                                int(d.copiedBytes),
                                int(d.totalFiles),
                                int(d.copiedFiles),
                                int(d.currentSpeedMBps),
                                int(d.isFinished),
                            )
                    except Exception:
                        win._audit_telemetry_snapshot = None
                if getattr(win, "_telemetry_view", None):
                    try:
                        _root.UnmapViewOfFile(win._telemetry_view)
                    except Exception:
                        pass
                    win._telemetry_view = None
                    win._telemetry_ptr = None
                for _name, h in shm_handles:
                    try:
                        _root.CloseHandle(h)
                    except Exception:
                        pass

        self.read_thread = threading.Thread(target=run, daemon=True)
        self.read_thread.start()

    def _update_progress_ui(self, prog: float, speed: float):
        if prog >= 99.9:
            self._last_display_progress = 100.0
        else:
            self._last_display_progress = prog
        display_prog = self._last_display_progress
        self.progress.setValue(int(min(1000, display_prog * 10)))
        elapsed = int(time.time() - self.engine_start_tick)
        eta = "--"
        if 0.1 < display_prog < 100 and display_prog > 0:
            eta_sec = int(elapsed / (display_prog / 100.0) - elapsed)
            if eta_sec > 0:
                eta = f"{eta_sec // 3600}:{(eta_sec % 3600) // 60:02d}:{eta_sec % 60:02d}"
        if self._mode_is_delete():
            spd_txt = f"{int(speed)} 项/秒" if speed > 0 else "-- 项/秒"
        else:
            spd_txt = f"{speed / 1024:.2f} GB/s" if speed >= 1024 else f"{speed:.1f} MB/s"
        self.lbl_telemetry.setText(f"速度: {spd_txt} | 进度: {display_prog:.1f}% | ETA: {eta}")
        self.last_speed = speed
        self.last_progress = display_prog

    def _set_primary_button_running(self, running: bool):
        act = "销毁" if self._mode_is_delete() else "复制"
        if running:
            self.btn_start.setText(f"■ 停止{act}")
            self.btn_start.setStyleSheet(
                "QPushButton#BtnStart { background-color: #c0392b; color: white; font-size: 15px; font-weight: bold; "
                "border: none; padding: 10px; border-radius: 4px; }"
            )
        else:
            self.btn_start.setText(f"▶ 开始{act}")
            self.btn_start.setStyleSheet(
                "QPushButton#BtnStart { background-color: #28a745; color: white; font-size: 15px; font-weight: bold; "
                "border: none; padding: 10px; border-radius: 4px; }"
            )

    def _on_engine_finished(self, exit_code: int, err_msg: str):
        self._run_line_timer.stop()
        self._run_line_pending = None
        self.is_running = False
        self.is_paused = False
        self._set_primary_button_running(False)
        self.lbl_engine_status.setText("任务完成 🔵" if not err_msg else "引擎离线 🔴")
        self.btn_pause.setEnabled(False)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setText("■ 停止")
        if self.pause_event_handle and _root.HAS_CTYPES:
            _root.CloseHandle(self.pause_event_handle)
            self.pause_event_handle = None
        if self.stop_event_handle and _root.HAS_CTYPES:
            _root.CloseHandle(self.stop_event_handle)
            self.stop_event_handle = None

        elapsed = int(time.time() - self.engine_start_tick)
        tel_fails = len(self.failed_files)

        if err_msg:
            self._append_log(f"\r\n--- 启动失败: {err_msg} ---\r\n", is_error=True)
            self._message(f"未能启动核心引擎: {err_msg}", "错误")
            return

        if exit_code != 0:
            self._append_log(f"\r\n--- 引擎异常退出 (Exit Code: {exit_code}) ---\r\n", is_error=True)
            self.lbl_engine_status.setText("引擎异常 🔴")
        else:
            self._append_log("\r\n--- COMPLETED ---\r\n")

        if exit_code == 2:
            self._message("目标盘空间不足！任务已中止。", "前置容量预检")
        if tel_fails > 0:
            self.btn_retry.setEnabled(True)
            self.btn_retry_admin.setEnabled(True)
            if (
                QMessageBox.question(
                    self,
                    "部分传输失败",
                    f"检出 {tel_fails} 个文件传输失败！是否查看失败日志？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self._write_failed_log_and_open()
        else:
            self.btn_retry.setEnabled(False)
            self.btn_retry_admin.setEnabled(False)

        if self.combo_post.currentText() == "自动关机":
            if (
                QMessageBox.question(
                    self, "自动关机", "任务已完成，是否立即关机？", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                == QMessageBox.StandardButton.Yes
            ):
                os.system("shutdown /s /t 0")

        self._generate_audit_report(exit_code, elapsed, tel_fails)

        if self.task_queue:
            qt = self.task_queue.popleft()
            self.entry_src.setText(qt["src"])
            self.entry_dst.setText(qt["dst"])
            if qt["is_delete"]:
                self.rad_delete.setChecked(True)
            else:
                self.rad_copy.setChecked(True)
            self._update_delete_mode_ui()
            QTimer.singleShot(500, self._on_start)

    def _on_stop(self):
        if not self.is_running:
            return
        if _root.HAS_CTYPES and getattr(self, "_telemetry_ptr", None):
            try:
                st = self._telemetry_ptr.contents
                st.data.cmd_Cancel = 1
                st.isDirty = 1
            except Exception:
                pass
        if _root.HAS_CTYPES and self.stop_event_handle:
            _root.SetEvent(self.stop_event_handle)
        self._append_log("\r\n--- 已请求停止 ---\r\n")
        self.btn_stop.setEnabled(False)
        self.btn_stop.setText("正在停止...")
        proc = self.process

        def force_kill_worker():
            try:
                if proc:
                    proc.wait(timeout=5)
            except Exception:
                pass
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    pass
            if proc and proc.poll() is None:
                try:
                    proc.kill()
                except Exception:
                    pass

        threading.Thread(target=force_kill_worker, daemon=True).start()

    def _on_pause(self):
        if not self.is_running or not self.process:
            return
        if not _root.HAS_CTYPES or not getattr(self, "_telemetry_ptr", None):
            self._append_log("\r\n--- 遥测未就绪，无法暂停 ---\r\n")
            return
        self.is_paused = not self.is_paused
        try:
            st = self._telemetry_ptr.contents
            st.data.cmd_Pause = 1 if self.is_paused else 0
            st.isDirty = 1
            if self.pause_event_handle:
                if self.is_paused:
                    # 手动复位：再暂停前必须清掉上次恢复留下的有信号状态
                    _root.ResetEvent(self.pause_event_handle)
                else:
                    _root.SetEvent(self.pause_event_handle)
        except Exception:
            pass
        self.btn_pause.setText("▶ 恢复" if self.is_paused else "⏸ 暂停")
        self._append_log("\r\n--- 任务已暂停 ---\r\n" if self.is_paused else "\r\n--- 任务已恢复 ---\r\n")

    def _on_retry(self):
        self._do_retry(admin=False)

    def _on_retry_admin(self):
        self._do_retry(admin=True)

    def _do_retry(self, admin=False):
        if not self.failed_files:
            return
        list_path = None
        try:
            import tempfile

            fd, list_path = tempfile.mkstemp(suffix=".txt", prefix="pb_retry_", text=True)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for line in self.failed_files:
                    path = line.split(" -> ")[-1].split("): ")[-1].strip()
                    if path and not path.startswith("["):
                        f.write(path + "\n")
        except Exception:
            list_path = None
        cmd, args, err = self._build_command_line(is_retry=True, list_path=list_path)
        if err:
            self._message(err, "错误")
            return
        self.failed_files.clear()
        self.btn_retry.setEnabled(False)
        self.btn_retry_admin.setEnabled(False)
        if admin:
            self._message("请右键以管理员身份运行本程序后重试。", "管理员重试")
            return
        self._start_engine(custom_cmd=cmd, custom_args=args)

    def _write_failed_log_and_open(self):
        try:
            import tempfile

            path = os.path.join(tempfile.gettempdir(), "PB_Failed_Items.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("--- PB X-Flow 失败项清单 ---\n\n")
                for line in self.failed_files:
                    f.write(line + "\n")
            if sys.platform == "win32":
                os.startfile(path)
        except Exception:
            pass

    def _generate_audit_report(self, exit_code, elapsed_sec, failed_count):
        dst = self.entry_dst.text().strip()
        if not dst:
            return
        is_del = self._mode_is_delete()
        prog_pct = float(self.last_progress)
        speed_val = float(self.last_speed)
        snap = getattr(self, "_audit_telemetry_snapshot", None)
        if snap and len(snap) >= 6:
            total_b, copied_b, total_f, copied_f, cur_spd, _finished = snap
            if elapsed_sec > 0:
                if not is_del and copied_b > 0:
                    speed_val = (copied_b / float(elapsed_sec)) / (1024.0 * 1024.0)
                elif is_del and copied_f > 0:
                    speed_val = copied_f / float(elapsed_sec)
            if total_b > 0:
                prog_pct = min(100.0, 100.0 * float(copied_b) / float(total_b))
            elif total_f > 0:
                prog_pct = min(100.0, 100.0 * float(copied_f) / float(total_f))
            if exit_code == 0 and failed_count == 0:
                if total_b > 0 and copied_b >= total_b:
                    prog_pct = 100.0
                elif total_b == 0 and total_f > 0 and copied_f >= total_f:
                    prog_pct = 100.0
            if speed_val <= 0 and cur_spd > 0 and not is_del:
                speed_val = float(cur_spd)
            if speed_val <= 0 and self.last_speed > 0:
                speed_val = float(self.last_speed)
            if prog_pct <= 0 and self.last_progress > 0:
                prog_pct = float(self.last_progress)
        try:
            base = dst.rstrip("\\/")
            now = datetime.now()
            fname = f"Migration_Audit_{now:%Y%m%d_%H%M%S}.html"
            path = os.path.join(base, fname)
            with open(path, "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE html><html><head><meta charset='UTF-8'><title>PB X-Flow 迁移审计</title>")
                f.write("<style>body{font-family:Segoe UI;margin:40px;background:#1e1e1e;color:#e0e0e0;}")
                f.write("h1{color:#00b4d8;}table{border-collapse:collapse;}th,td{border:1px solid #444;padding:10px;}")
                f.write(".fail{color:#f44336;}.ok{color:#4caf50;}</style></head><body>")
                f.write("<h1>PB X-Flow 迁移审计报告</h1>")
                f.write(f"<p><b>生成时间</b>: {now:%Y-%m-%d %H:%M:%S}</p>")
                if is_del:
                    f.write(f"<p><b>待销毁目录</b>: {dst}</p>")
                else:
                    f.write(f"<p><b>源路径</b>: {self.entry_src.text()}</p>")
                    f.write(f"<p><b>目标路径</b>: {dst}</p>")
                f.write(f"<p><b>总耗时</b>: {elapsed_sec} 秒</p>")
                if is_del:
                    spd_line = f"{speed_val:.1f} 项/秒" if speed_val > 0 else "--"
                else:
                    spd_line = f"{speed_val:.2f} MB/s" if speed_val > 0 else "--"
                f.write(f"<p><b>平均速度</b>: {spd_line}</p>")
                f.write(f"<p><b>完成进度</b>: {prog_pct:.1f}%</p>")
                f.write(f"<p><b>退出码</b>: {exit_code}</p>")
                f.write(f"<p><b>失败文件数</b>: <span class='{'fail' if failed_count else 'ok'}'>{failed_count}</span></p>")
                if failed_count and self.failed_files:
                    f.write("<h2>失败清单</h2><ul>")
                    for line in self.failed_files:
                        p = line.split(" -> ")[-1].split("): ")[-1].strip() or line
                        f.write(f"<li>{p}</li>")
                    f.write("</ul>")
                f.write("</body></html>")
        except Exception:
            pass

    def _on_preflight(self):
        if self._preflight_busy:
            return
        if self._mode_is_delete():
            self._message("预检仅用于复制/同步；极速销毁请确认「待销毁目录」后使用开始按钮。", "预检")
            return
        src = self.entry_src.text().strip().replace("/", "\\")
        dst = self.entry_dst.text().strip().replace("/", "\\")
        if not src or not dst:
            self._message("请填写源路径和目标路径。", "预检")
            return
        work_dir = os.path.dirname(self.engine_path) or "."
        cmd = [self.engine_path, "-s", src, "-d", dst, "-preflight", "-z"]
        self._preflight_busy = True
        self.btn_preflight.setEnabled(False)
        self.btn_preflight.setText("…")

        def worker():
            err = None
            gb_val = total_val = None
            tmp_path = None
            try:
                # 预检时引擎会持续向 stdout 打印进度；用 PIPE + capture_output 会填满管道缓冲区，
                # 子进程阻塞在 wprintf 上、父进程在等进程结束，形成死锁，表现为固定秒数超时。
                fd, tmp_path = tempfile.mkstemp(prefix="pb_preflight_", suffix=".log")
                os.close(fd)
                creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                with open(tmp_path, "wb") as outf:
                    subprocess.run(
                        cmd,
                        shell=False,
                        stdout=outf,
                        stderr=subprocess.STDOUT,
                        cwd=work_dir,
                        creationflags=creationflags,
                        timeout=None,
                    )
                with open(tmp_path, "rb") as inf:
                    raw = inf.read()
                out = raw.decode(_root.ENGINE_STDOUT_ENCODING, errors="replace")
                m = re.search(r"PREFLIGHT_TOTAL_BYTES=(\d+)", out)
                if m:
                    total_val = int(m.group(1))
                    gb_val = total_val / (1024**3)
            except Exception as e:
                err = str(e)
            finally:
                if tmp_path:
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
            self._bridge.preflight_done_sig.emit(err if err else "", gb_val, total_val)

        threading.Thread(target=worker, daemon=True).start()

    def _on_preflight_done(self, err: str, gb_val: object, total_val: object):
        self._preflight_busy = False
        self.btn_preflight.setEnabled(True)
        self.btn_preflight.setText("预检")
        if err:
            self._message(f"预检失败: {err}", "错误")
        elif gb_val is not None and total_val is not None:
            self._message(f"预检完成，总大小: {gb_val:.2f} GB ({total_val:,} 字节)", "预检")
        else:
            self._message("预检未返回有效数据，请检查路径。", "预检")

    def _on_help(self):
        self._message(
            "PB X-Flow V123 - 企业级高速文件复制\n\n"
            "大文件: -B 64 -q 8 -t 64 -F -W\n"
            "小文件: -J -j 512 -t 24 -F -W\n"
            "混合: -J -j 256 -B 32 -q 8 -t 64 -F",
            "帮助",
        )

    def _on_about(self):
        self._message("PB X-Flow Ver123\n企业级高速文件复制 / 同步图形界面\n\n" + _root.COPYRIGHT_TEXT, "关于")

    def _on_defender(self):
        self._message(
            "勾选任务页「常用」中的「Defender 排除」后启动复制：\n"
            "引擎会按需弹出 UAC。\n",
            "Defender 排除",
        )

    def _on_reg_context_menu(self):
        if sys.platform != "win32" or _root.winreg is None:
            self._message("仅 Windows 支持注册右键菜单。", "提示")
            return
        if _root.is_admin():
            try:
                _root.do_reg_context_menu()
                self._message(
                    "右键菜单已添加。\n在文件夹上右键可看到「PB X-Flow」项，将以该目录为源路径。",
                    "成功",
                )
            except Exception as e:
                self._message(str(e), "错误")
            return
        try:
            import ctypes

            if _root._is_frozen_or_compiled_module():
                exe = sys.executable
                params = "--reg-menu"
            else:
                # 与注册表 command 一致：用 argv[0] 锚定的 REAL_EXE_PATH，避免 __file__ 与入口脚本不一致
                exe = sys.executable
                params = subprocess.list2cmdline([_root.REAL_EXE_PATH, "--reg-menu"])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", exe, params, _root.BASE_DIR or os.path.dirname(_root.REAL_EXE_PATH) or ".", 1
            )
        except Exception as e:
            self._message(str(e), "错误")

    def _on_unreg_context_menu(self):
        if sys.platform != "win32" or _root.winreg is None:
            self._message("仅 Windows 支持。", "提示")
            return
        if not _root.is_admin():
            self._message(
                "删除右键菜单需要管理员权限。\n请右键以管理员身份运行本程序后，在「工具」中再次选择此项。",
                "权限",
            )
            return
        try:
            _root.do_unreg_context_menu()
            self._message("已移除右键菜单。", "成功")
        except Exception as e:
            self._message(str(e), "错误")

    def _on_open_manual_pdf(self):
        for p in _root._manual_candidates():
            if os.path.isfile(p):
                try:
                    if sys.platform == "win32":
                        os.startfile(p)
                    else:
                        subprocess.run(["xdg-open", p], check=False)
                    return
                except Exception as e:
                    self._message(f"无法打开文件:\n{e}", "错误")
                    return
        self._message(
            f"未找到使用手册文件：\n{_root.MANUAL_FILE_NAME}\n\n请将其与本程序放在同一文件夹下。",
            "提示",
        )

    def _on_show_copyright_dialog(self):
        self._message(_root.COPYRIGHT_TEXT, "版权信息")

    def _on_open_history_folder(self):
        log_dir = _root.get_log_dir()
        if os.path.isdir(log_dir) and sys.platform == "win32":
            try:
                os.startfile(log_dir)
            except Exception as e:
                self._message(str(e), "错误")
        else:
            self._message("尚无日志目录。", "提示")

    def _message(self, msg: str, title: str = "PB X-Flow", ask: bool = False):
        if ask:
            return (
                QMessageBox.question(self, title, msg, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
                == QMessageBox.StandardButton.Yes
            )
        QMessageBox.information(self, title, msg)

    def closeEvent(self, event):
        self._save_config()
        if self.is_running:
            if (
                QMessageBox.question(
                    self,
                    "确认",
                    "任务正在运行，是否停止并退出？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                event.ignore()
                return
            self._on_stop()
        event.accept()
        if self._tray_icon:
            self._tray_icon.hide()
        app = QApplication.instance()
        if app:
            app.quit()


def run_qt_app(initial_src: str | None) -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setFont(QFont("Microsoft YaHei UI", 10))
    _ip = _root.get_icon_path()
    if _ip and os.path.isfile(_ip):
        app.setWindowIcon(QIcon(_ip))
    # WindowsVista 样式常忽略 QComboBox 下拉 / QMessageBox 的部分 QSS，Fusion 与深色主题一致
    try:
        app.setStyle("Fusion")
    except Exception:
        pass
    app.setStyleSheet(PB_XFLOW_APP_STYLESHEET)
    w = PBXFlowWindow()
    if initial_src:
        w.entry_src.setText(initial_src)
    # 副实例壳菜单路径交接
    try:
        _root.process_pending_paths(w)
        w.ipc_timer = QTimer(w)
        w.ipc_timer.setInterval(800)
        w.ipc_timer.timeout.connect(lambda: _root.process_pending_paths(w))
        w.ipc_timer.start()
    except Exception:
        pass
    w.show()
    return app.exec()
