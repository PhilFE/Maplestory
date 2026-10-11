import ctypes
import sys
import os

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # 判断是否为打包后的exe
    if getattr(sys, 'frozen', False):
        # 如果是打包后的程序，sys.executable 就是exe本身
        script = sys.executable
    else:
        # 如果是普通脚本，sys.executable 是python解释器，脚本路径在 sys.argv[0]
        script = os.path.abspath(sys.argv[0])
    
    # 请求提权并重新运行
    # 参数依次为：父窗口句柄, 操作, 可执行文件, 参数, 目录, 显示方式
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, script, None, 1
    )
    sys.exit()

# -*- coding: utf-8 -*-
# ============================================================
# 自动上 Buff + 长按攻击工具 v1.9
# 新增：
#   鼠标控制方向（巡逻模式）：根据鼠标在窗口左/中/右决定方向
# 保留：
#   1. 巡逻转向延迟：到达换向点先松开方向键 → 原地跳 N 秒 → 换向
#   2. 步进模式：关 / 回头模式 / 前进模式
#   3. 攻击模式：长按 / 跳跃 / 巡逻跳跃
# F8 = 总开关   F9 = 强制关闭
# ============================================================
import sys, os, time, json, threading, uuid
from pathlib import Path
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QLabel, QTextEdit, QCheckBox, QLineEdit, QDoubleSpinBox,
    QDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QStatusBar, QAbstractItemView, QComboBox, QTabWidget
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
import ctypes
from ctypes import wintypes

user32 = ctypes.windll.user32


class POINT(ctypes.Structure):
    _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]


VK_CODES = {
    'left':0x25,'up':0x26,'right':0x27,'down':0x28,'ctrl':0x11,'alt':0x12,'shift':0x10,
    'a':0x41,'b':0x42,'c':0x43,'d':0x44,'e':0x45,'f':0x46,'g':0x47,'h':0x48,'i':0x49,'j':0x4A,
    'k':0x4B,'l':0x4C,'m':0x4D,'n':0x4E,'o':0x4F,'p':0x50,'q':0x51,'r':0x52,'s':0x53,'t':0x54,
    'u':0x55,'v':0x56,'w':0x57,'x':0x58,'y':0x59,'z':0x5A,'delete':0x2E,'insert':0x2D,
    'pgup':0x21,'pgdown':0x22,'end':0x23,'home':0x24,'space':0x20,'enter':0x0D,'esc':0x1B,'tab':0x09,
    'f1':0x70,'f2':0x71,'f3':0x72,'f4':0x73,'f5':0x74,'f6':0x75,'f7':0x76,'f8':0x77,'f9':0x78,
    'f10':0x79,'f11':0x7A,'f12':0x7B,'0':0x30,'1':0x31,'2':0x32,'3':0x33,'4':0x34,
    '5':0x35,'6':0x36,'7':0x37,'8':0x38,'9':0x39
}
SCAN_CODES = {
    'left':0x4B,'up':0x48,'right':0x4D,'down':0x50,'delete':0x53,'insert':0x52,
    'pgup':0x49,'pageup':0x49,'pgdown':0x51,'pagedown':0x51,'end':0x4F,'home':0x47,
    'ctrl':0x1D,'alt':0x38,'shift':0x2A,'a':0x1E,'b':0x30,'c':0x2E,'d':0x20,'e':0x12,
    'f':0x21,'g':0x22,'h':0x23,'i':0x17,'j':0x24,'k':0x25,'l':0x26,'m':0x32,'n':0x31,'o':0x18,
    'p':0x19,'q':0x10,'r':0x13,'s':0x1F,'t':0x14,'u':0x16,'v':0x2F,'w':0x11,'x':0x2D,'y':0x15,'z':0x2C,
    'space':0x39,'enter':0x1C,'esc':0x01,'tab':0x0F,'f1':0x3B,'f2':0x3C,'f3':0x3D,'f4':0x3E,'f5':0x3F,
    'f6':0x40,'f7':0x41,'f8':0x42,'f9':0x43,'f10':0x44,'f11':0x57,'f12':0x58,
    '0':0x0B,'1':0x02,'2':0x03,'3':0x04,'4':0x05,'5':0x06,'6':0x07,'7':0x08,'8':0x09,'9':0x0A
}
EXTENDED_KEYS = {'left','up','right','down','delete','insert','pgup','pageup','pgdown','pagedown','end','home'}
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_EXTENDEDKEY = 0x0001

DIRECTION_KEYS = ['left', 'right']
DIRECTION_CN = {'left': '左', 'right': '右', 'up': '上', 'down': '下'}
OPPOSITE = {'left': 'right', 'right': 'left', 'up': 'down', 'down': 'up'}

KEY_OPTIONS = ['ctrl','alt','shift','space','enter','tab','esc',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t',
    'u','v','w','x','y','z',
    'f1','f2','f3','f4','f5','f6','f7','f8','f9','f10','f11','f12',
    'delete','insert','pgup','pgdown','end','home',
    '0','1','2','3','4','5','6','7','8','9']

ATTACK_MODES = [
    ('hold', '长按攻击'),
    ('jump', '跳跃攻击'),
    ('patrol_jump', '巡逻跳跃攻击（标飞）'),
]

STEP_MODES = [
    ('off', '关（不步进）'),
    ('backward', '回头模式'),
    ('forward', '前进模式'),
]


class Win32Input:
    @staticmethod
    def key_down(key):
        k = key.lower()
        vk = VK_CODES.get(k, 0)
        if not vk:
            return False
        scan = SCAN_CODES.get(k, 0)
        flags = KEYEVENTF_EXTENDEDKEY if k in EXTENDED_KEYS else 0
        user32.keybd_event(vk, scan, flags, 0)
        return True

    @staticmethod
    def key_up(key):
        k = key.lower()
        vk = VK_CODES.get(k, 0)
        if not vk:
            return False
        scan = SCAN_CODES.get(k, 0)
        flags = (KEYEVENTF_EXTENDEDKEY if k in EXTENDED_KEYS else 0) | KEYEVENTF_KEYUP
        user32.keybd_event(vk, scan, flags, 0)
        return True

    @staticmethod
    def set_foreground(hwnd):
        try:
            if user32.IsIconic(hwnd):
                user32.ShowWindow(hwnd, 9)
            user32.SetForegroundWindow(hwnd)
            time.sleep(0.08)
            return True
        except Exception:
            return False


def parse_keys(s):
    if not s:
        return []
    s = s.strip().lower()
    if '+' in s:
        return [p.strip() for p in s.split('+') if p.strip()]
    return [s]


class GameWindowDetector:
    EXCLUDE = ['自动挂机','挂机工具','辅助工具','companion','agent','控制台',
               '豆包','系统设置','auto_buff','Python','Buff工具']

    def __init__(self):
        self._dpi = False

    def _ensure_dpi(self):
        if not self._dpi:
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                try:
                    user32.SetProcessDPIAware()
                except Exception:
                    pass
            self._dpi = True

    def find_window(self, keywords_str):
        self._ensure_dpi()
        kws = [k.strip() for k in keywords_str.split(',') if k.strip()]
        found = []

        def cb(hwnd, _):
            if not user32.IsWindowVisible(hwnd):
                return True
            l = user32.GetWindowTextLengthW(hwnd)
            if l == 0:
                return True
            buf = ctypes.create_unicode_buffer(l + 1)
            user32.GetWindowTextW(hwnd, buf, l + 1)
            t = buf.value
            if any(k in t for k in kws) and not any(e in t for e in self.EXCLUDE):
                r = wintypes.RECT()
                user32.GetClientRect(hwnd, ctypes.byref(r))
                w = r.right - r.left
                h = r.bottom - r.top
                if w > 200 and h > 200:
                    pt = wintypes.POINT(0, 0)
                    user32.ClientToScreen(hwnd, ctypes.byref(pt))
                    found.append({'hwnd': hwnd, 'title': t, 'x': pt.x, 'y': pt.y, 'w': w, 'h': h})
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows(WNDENUMPROC(cb), 0)
        return found[0] if found else None


class BotSignals(QThread):
    log = pyqtSignal(str)
    state = pyqtSignal(str)


# ==================== 攻击线程 ====================
class AttackWorker(threading.Thread):
    def __init__(self, bot):
        super().__init__(daemon=True)
        self.bot = bot
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_ack = threading.Event()
        self._held = set()
        self._direction_fixed = False
        self._was_active = False
        self._last_mode = None

        # 巡逻状态
        self._patrol_direction = None
        self._patrol_change_t = 0.0
        self._patrol_turn_pending_since = None
        self._patrol_inited = False
        self._patrol_use_mouse_last = None

    @property
    def config(self):
        return self.bot.config

    @property
    def input(self):
        return self.bot.input

    def log(self, m):
        self.bot.log(m)

    def _key_down(self, k):
        if k and k not in self._held:
            self.input.key_down(k)
            self._held.add(k)

    def _key_up(self, k):
        if k in self._held:
            self.input.key_up(k)
            self._held.discard(k)

    def _release_all(self):
        for k in list(self._held):
            self.input.key_up(k)
        self._held.clear()

    def _pause_and_ack(self):
        self._release_all()
        self.pause_ack.set()

    def _sleep_interruptible(self, sec):
        end = time.time() + sec
        while time.time() < end:
            if self.stop_event.is_set():
                return True
            if self.pause_event.is_set():
                self._pause_and_ack()
                return True
            time.sleep(0.01)
        return False

    # -------- 鼠标位置 → 方向 --------
    def _get_mouse_direction(self):
        """
        鼠标在游戏窗口左半边 → 'left'
        鼠标在游戏窗口右半边 → 'right'
        鼠标在中间死区 / 窗口外 → None（停止移动）
        """
        if not self.bot.game_window:
            return None
        try:
            pt = POINT()
            if not user32.GetCursorPos(ctypes.byref(pt)):
                return None
            wx = self.bot.game_window['x']
            ww = self.bot.game_window['w']
            if ww <= 0:
                return None
            mx = pt.x - wx
            if mx < 0 or mx > ww:
                return None
            deadzone = float(self.config['attack'].get('mouse_deadzone', 0.20))
            deadzone = max(0.0, min(0.9, deadzone))
            left_bound = ww * (0.5 - deadzone / 2)
            right_bound = ww * (0.5 + deadzone / 2)
            if mx < left_bound:
                return 'left'
            elif mx > right_bound:
                return 'right'
            else:
                return None
        except Exception:
            return None

    def _reset_patrol(self):
        if self._patrol_direction and self._patrol_direction in self._held:
            self._key_up(self._patrol_direction)
        self._patrol_direction = None
        self._patrol_turn_pending_since = None
        self._patrol_inited = False

    # -------- 主循环 --------
    def run(self):
        self.log("[攻击线程] 已启动")
        last_step = time.time()
        while not self.stop_event.is_set():
            cfg = self.config.get('attack', {})
            active = cfg.get('enabled', False) and self.bot.master_enabled

            if not active:
                self._release_all()
                if self._was_active:
                    self._direction_fixed = False
                    self._was_active = False
                    self._reset_patrol()
                    self._last_mode = None
                last_step = time.time()
                time.sleep(0.1)
                continue

            mode = cfg.get('mode', 'hold')
            if mode != self._last_mode:
                self._release_all()
                self._reset_patrol()
                self._patrol_change_t = time.time()
                last_step = time.time()
                self._last_mode = mode

            if not self._direction_fixed:
                self._release_all()
                if not self.bot.game_window:
                    if not self.bot.find_window():
                        time.sleep(0.5)
                        continue
                self.input.set_foreground(self.bot.game_window['hwnd'])
                time.sleep(0.1)
                d = cfg.get('direction', 'right')
                self.log(f"[攻击] 修正朝向：{DIRECTION_CN.get(d, d)}")
                self.input.key_down(d)
                time.sleep(0.06)
                self.input.key_up(d)
                time.sleep(0.08)
                self._direction_fixed = True
                self._was_active = True
                last_step = time.time()

            if self.pause_event.is_set():
                self._pause_and_ack()
                time.sleep(0.05)
                continue

            if not self.bot.game_window:
                self._release_all()
                time.sleep(0.3)
                continue

            step_mode = cfg.get('step_mode', 'off')
            if mode != 'patrol_jump' and step_mode != 'off':
                step_interval = float(cfg.get('step_interval', 60))
                if time.time() - last_step >= step_interval:
                    self._do_step()
                    last_step = time.time()
                    continue

            if mode == 'patrol_jump':
                self._do_patrol_jump_attack()
            elif mode == 'jump':
                self._do_jump_attack()
            else:
                self._do_hold_attack()

        self._release_all()
        self.log("[攻击线程] 已退出")

    # -------- 长按攻击 --------
    def _do_hold_attack(self):
        cfg = self.config['attack']
        atk = cfg.get('key', 'ctrl')
        self._key_down(atk)
        time.sleep(0.02)

    # -------- 跳跃攻击 --------
    def _do_jump_attack(self):
        cfg = self.config['attack']
        atk = cfg.get('key', 'ctrl')
        jump = cfg.get('jump_key', 'alt')
        cycle_ms = int(cfg.get('jump_cycle_ms', 700))
        atk_delay_ms = int(cfg.get('jump_atk_delay_ms', 50))
        atk_hold_ms = int(cfg.get('jump_atk_hold_ms', 100))

        self._release_all()

        self._key_down(jump)
        if self._sleep_interruptible(atk_delay_ms / 1000.0):
            return
        self._key_down(atk)
        if self._sleep_interruptible(atk_hold_ms / 1000.0):
            return
        self._key_up(atk)
        self._key_up(jump)

        elapsed_ms = atk_delay_ms + atk_hold_ms
        remaining_ms = max(0, cycle_ms - elapsed_ms)
        if remaining_ms > 0:
            self._sleep_interruptible(remaining_ms / 1000.0)

    # -------- 巡逻跳跃攻击 --------
    def _do_patrol_jump_attack(self):
        cfg = self.config['attack']
        atk = cfg.get('key', 'ctrl')
        jump = cfg.get('jump_key', 'alt')
        cycle_ms = int(cfg.get('jump_cycle_ms', 700))
        atk_delay_ms = int(cfg.get('jump_atk_delay_ms', 50))
        atk_hold_ms = int(cfg.get('jump_atk_hold_ms', 100))
        change_int = float(cfg.get('patrol_change_interval', 8.0))
        turn_delay = float(cfg.get('patrol_turn_delay', 0.0))
        use_mouse = bool(cfg.get('patrol_use_mouse', False))

        # 鼠标模式切换 → 重置巡逻状态
        if self._patrol_use_mouse_last != use_mouse:
            self._reset_patrol()
            self._patrol_change_t = time.time()
            self._patrol_use_mouse_last = use_mouse

        # 初始化
        if not self._patrol_inited:
            self._patrol_inited = True
            self._patrol_change_t = time.time()
            self._patrol_turn_pending_since = None
            if use_mouse:
                self._patrol_direction = None
                self.log("[巡逻-鼠标] 启动，方向由鼠标位置控制（左 / 中 / 右）")
            else:
                self._patrol_direction = cfg.get('direction', 'right')
                self._key_down(self._patrol_direction)
                self.log(f"[巡逻] 起始方向：{DIRECTION_CN.get(self._patrol_direction)}")

        now = time.time()

        if use_mouse:
            # ============ 鼠标模式 ============
            new_dir = self._get_mouse_direction()

            if new_dir != self._patrol_direction:
                # 方向变了：释放旧方向
                if self._patrol_direction and self._patrol_direction in self._held:
                    self._key_up(self._patrol_direction)
                # 按新方向
                if new_dir:
                    self._key_down(new_dir)
                    self.log(f"[巡逻-鼠标] 方向：{DIRECTION_CN.get(new_dir)}")
                else:
                    self.log("[巡逻-鼠标] 方向：停止（鼠标在中间区域）")
                self._patrol_direction = new_dir
            else:
                # 方向相同，但暂停恢复后按键可能被释放 → 重新按下
                if new_dir and new_dir not in self._held:
                    self._key_down(new_dir)

            # 鼠标模式不处理换向计时器
            self._patrol_turn_pending_since = None

        else:
            # ============ 定时换向模式（原逻辑） ============
            if self._patrol_turn_pending_since is None:
                # 阶段A：正常巡逻
                if now - self._patrol_change_t >= change_int:
                    if turn_delay > 0:
                        # 进入阶段B：先松开方向键
                        if self._patrol_direction in self._held:
                            self._key_up(self._patrol_direction)
                        self._patrol_turn_pending_since = now
                        self.log(
                            f"[巡逻] 到达换向点，松开方向键，原地跳跃攻击 "
                            f"{turn_delay:.1f}s 后转向"
                        )
                    else:
                        # 立即换向
                        old_d = self._patrol_direction
                        new_d = OPPOSITE.get(old_d, old_d)
                        self._key_up(old_d)
                        self._patrol_direction = new_d
                        self._patrol_change_t = now
                        self._key_down(new_d)
                        self.log(
                            f"[巡逻] 换向 {DIRECTION_CN.get(old_d)} → {DIRECTION_CN.get(new_d)}"
                        )
                else:
                    # 确保方向键按住
                    pd = self._patrol_direction
                    if pd and pd not in self._held:
                        self._key_down(pd)
                        self._patrol_change_t = time.time()
            else:
                # 阶段B：延迟中（方向键保持松开）
                if self._patrol_direction in self._held:
                    self._key_up(self._patrol_direction)
                if now - self._patrol_turn_pending_since >= turn_delay:
                    old_d = self._patrol_direction
                    new_d = OPPOSITE.get(old_d, old_d)
                    self._patrol_direction = new_d
                    self._patrol_change_t = now
                    self._patrol_turn_pending_since = None
                    self._key_down(new_d)
                    self.log(
                        f"[巡逻] 换向 {DIRECTION_CN.get(old_d)} → {DIRECTION_CN.get(new_d)}"
                    )

        # ============ 跳跃攻击（两个模式都执行） ============
        self._key_up(atk)
        self._key_up(jump)

        self._key_down(jump)
        if self._sleep_interruptible(atk_delay_ms / 1000.0):
            return
        self._key_down(atk)
        if self._sleep_interruptible(atk_hold_ms / 1000.0):
            return
        self._key_up(atk)
        self._key_up(jump)

        elapsed_ms = atk_delay_ms + atk_hold_ms
        remaining_ms = max(0, cycle_ms - elapsed_ms)
        if remaining_ms > 0:
            self._sleep_interruptible(remaining_ms / 1000.0)

    # -------- 步进 --------
    def _do_step(self):
        cfg = self.config.get('attack', {})
        step_mode = cfg.get('step_mode', 'off')
        if step_mode == 'off':
            return

        face = cfg.get('direction', 'right')
        opposite = OPPOSITE.get(face, face)
        atk = cfg.get('key', 'ctrl')
        fwd = float(cfg.get('step_forward', 1.5))
        atk_t = float(cfg.get('step_attack', 0.3))
        bwd = float(cfg.get('step_backward', 1.5))
        turn_hold = float(cfg.get('turn_hold', 0.06))

        self._release_all()
        time.sleep(0.05)

        if step_mode == 'forward':
            self.log(f"[步进-前进] 前进{fwd:.1f}s → 攻击{atk_t:.1f}s → 返回{bwd:.1f}s → 转向")

            self._key_down(face)
            if self._sleep_interruptible(fwd):
                return
            self._key_up(face)
            time.sleep(0.05)

            self._key_down(atk)
            if self._sleep_interruptible(atk_t):
                return
            self._key_up(atk)
            time.sleep(0.05)

            self._key_down(opposite)
            if self._sleep_interruptible(bwd):
                return
            self._key_up(opposite)
            time.sleep(0.05)

            self._release_all()
            time.sleep(0.03)
            self._key_down(face)
            if self._sleep_interruptible(turn_hold):
                return
            self._key_up(face)
            time.sleep(0.10)

            self.log("[步进-前进] 完成")

        else:
            self.log(f"[步进-回头] 后退{bwd:.1f}s → 攻击{atk_t:.1f}s → 回位{fwd:.1f}s")

            self._key_down(opposite)
            if self._sleep_interruptible(bwd):
                return
            self._key_up(opposite)
            time.sleep(0.05)

            self._key_down(atk)
            if self._sleep_interruptible(atk_t):
                return
            self._key_up(atk)
            time.sleep(0.05)

            self._key_down(face)
            if self._sleep_interruptible(fwd):
                return
            self._key_up(face)
            time.sleep(0.05)

            self._release_all()
            time.sleep(0.10)

            self.log("[步进-回头] 完成")

    def shutdown(self):
        self.stop_event.set()
        self.pause_event.set()
        self._release_all()


# ==================== Buff 主控 ====================
class BuffBot:
    def __init__(self, config, signals):
        self.config = config
        self.signals = signals
        self.input = Win32Input()
        self.detector = GameWindowDetector()
        self.game_window = None
        self.master_enabled = False
        self.stop_event = threading.Event()
        self.last_cast = {}
        self._last_any_cast = 0
        self.attack_worker = AttackWorker(self)

    def log(self, m):
        self.signals.log.emit(m)

    def find_window(self):
        kw = self.config.get('window_keywords', 'MapleStory,冒险岛怀旧服')
        win = self.detector.find_window(kw)
        if win:
            self.game_window = win
            self.log(f"[√] 找到窗口: {win['title']} ({win['w']}x{win['h']})")
            return True
        self.game_window = None
        return False

    def cast(self, buff):
        if not self.game_window:
            return
        keys = parse_keys(buff.get('keys_str', ''))
        if not keys:
            self.log(f"[!] {buff.get('name')}: 按键为空")
            return
        self.input.set_foreground(self.game_window['hwnd'])
        time.sleep(0.08)
        self.log(f"[Buff] {buff.get('name')} -> {'+'.join(keys)}")
        for k in keys:
            self.input.key_down(k)
            time.sleep(0.03)
        time.sleep(0.05)
        for k in reversed(keys):
            self.input.key_up(k)
            time.sleep(0.03)

    def _pause_attack_and_wait(self, timeout=0.8):
        aw = self.attack_worker
        aw.pause_ack.clear()
        aw.pause_event.set()
        ok = aw.pause_ack.wait(timeout=timeout)
        time.sleep(0.15)
        return ok

    def _resume_attack(self):
        self.attack_worker.pause_event.clear()
        time.sleep(0.05)

    def loop(self):
        self.log("[*] Buff 主循环已启动")
        while not self.stop_event.is_set():
            if not self.master_enabled or not self.config.get('buffs_enabled', True):
                time.sleep(0.15)
                continue
            if not self.game_window or not user32.IsWindow(self.game_window['hwnd']):
                self.log("[!] 游戏窗口失效，重新查找...")
                if not self.find_window():
                    time.sleep(1.0)
                    continue
            buffs = list(self.config.get('buffs', []))
            now = time.time()
            valid_ids = {b.get('id') for b in buffs}
            for k in list(self.last_cast.keys()):
                if k not in valid_ids:
                    del self.last_cast[k]
            buff_interval = float(self.config.get('buff_interval', 1.0))
            casted = False
            for buff in buffs:
                if not buff.get('enabled', True):
                    continue
                bid = buff.get('id')
                interval = float(buff.get('interval', 180))
                last = self.last_cast.get(bid, 0)
                if now - last < interval:
                    continue
                wait = buff_interval - (time.time() - self._last_any_cast)
                if wait > 0:
                    if self.stop_event.wait(wait):
                        break
                if self.stop_event.is_set():
                    break

                pause_attack = self.config.get('pause_attack_on_buff', True)
                if pause_attack:
                    ok = self._pause_attack_and_wait(timeout=0.8)
                    if not ok:
                        self.log("[!] 攻击线程暂停超时，仍然尝试上 Buff")

                self.cast(buff)
                self._last_any_cast = time.time()
                self.last_cast[bid] = time.time()
                casted = True

                if pause_attack:
                    self._resume_attack()
                break
            if not casted:
                time.sleep(0.15)
        self.log("[*] Buff 主循环已退出")

    def set_master(self, enabled):
        self.master_enabled = bool(enabled)
        if enabled:
            self.last_cast.clear()
            self._last_any_cast = 0
            if self.game_window:
                self.input.set_foreground(self.game_window['hwnd'])
            self.log("[▶] 总开关：开启")
        else:
            self.attack_worker.pause_event.set()
            self.log("[⏸] 总开关：关闭")

    def start_worker(self):
        if not self.attack_worker.is_alive():
            self.attack_worker.start()

    def shutdown(self):
        self.stop_event.set()
        self.attack_worker.shutdown()


# ==================== Buff 编辑对话框 ====================
class BuffDialog(QDialog):
    def __init__(self, parent=None, buff=None):
        super().__init__(parent)
        self.setWindowTitle("编辑 Buff" if buff else "添加 Buff")
        self.setMinimumWidth(360)
        form = QFormLayout(self)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("例如：攻击Buff / 祝福 / 加速")
        self.keys_edit = QLineEdit()
        self.keys_edit.setPlaceholderText("单个按键：f1   组合键：ctrl+x")
        self.interval_spin = QDoubleSpinBox()
        self.interval_spin.setRange(1, 7200)
        self.interval_spin.setValue(180)
        self.interval_spin.setSuffix(" 秒")
        self.interval_spin.setSingleStep(5)
        self.enabled_cb = QCheckBox("启用此 Buff")
        self.enabled_cb.setChecked(True)
        tip = QLabel("提示：间隔 = 每隔多少秒按一次。\n建议 = Buff持续时间 - 3~5 秒。")
        tip.setStyleSheet("color:#2d8cf0;font-size:11px;")
        form.addRow("名称", self.name_edit)
        form.addRow("按键", self.keys_edit)
        form.addRow("间隔", self.interval_spin)
        form.addRow("", self.enabled_cb)
        form.addRow(tip)
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        form.addRow(btns)
        if buff:
            self.name_edit.setText(buff.get('name', ''))
            self.keys_edit.setText(buff.get('keys_str', ''))
            self.interval_spin.setValue(float(buff.get('interval', 180)))
            self.enabled_cb.setChecked(bool(buff.get('enabled', True)))

    def get_buff(self):
        return {
            'name': self.name_edit.text().strip() or '未命名Buff',
            'keys_str': self.keys_edit.text().strip().lower(),
            'interval': float(self.interval_spin.value()),
            'enabled': self.enabled_cb.isChecked(),
        }

    def accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "提示", "请输入名称")
            return
        if not parse_keys(self.keys_edit.text().strip()):
            QMessageBox.warning(self, "提示", "请输入按键，例如 f1 或 ctrl+x")
            return
        bad = [k for k in parse_keys(self.keys_edit.text().strip()) if k not in VK_CODES]
        if bad:
            QMessageBox.warning(self, "提示", f"不支持的按键：{', '.join(bad)}")
            return
        super().accept()


# ==================== 主窗口 ====================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.config = {
            'master_enabled': False,
            'window_keywords': 'MapleStory,冒险岛怀旧服',
            'buff_interval': 1.0,
            'buffs_enabled': True,
            'pause_attack_on_buff': True,
            'buffs': [],
            'attack': {
                'enabled': False,
                'mode': 'hold',
                'direction': 'right',
                'key': 'ctrl',
                'jump_key': 'alt',
                'jump_cycle_ms': 700,
                'jump_atk_delay_ms': 50,
                'jump_atk_hold_ms': 100,
                'patrol_change_interval': 8.0,
                'patrol_turn_delay': 2.0,
                'patrol_use_mouse': False,     # ★ 鼠标控制方向
                'mouse_deadzone': 0.20,        # ★ 中间死区（0~0.9）
                'step_mode': 'forward',
                'step_interval': 60.0,
                'step_forward': 1.5,
                'step_attack': 0.3,
                'step_backward': 1.5,
                'turn_hold': 0.06,
            },
        }
        self.signals = BotSignals()
        self.bot = BuffBot(self.config, self.signals)
        self._updating_table = False
        self._f8_prev = False
        self._f9_prev = False

        self._init_ui()
        self._connect_signals()
        self._load_config()
        self._rebuild_table()
        self._sync_ui_from_config()

        self.bot.start_worker()
        threading.Thread(target=self.bot.loop, daemon=True).start()

        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self._tick)
        self.refresh_timer.start(300)

    def _init_ui(self):
        self.setWindowTitle("自动上 Buff + 长按攻击 v1.9")
        self.setMinimumSize(820, 880)
        c = QWidget()
        self.setCentralWidget(c)
        lay = QVBoxLayout(c)

        top = QHBoxLayout()
        self.master_cb = QCheckBox("★ 总开关（F8）")
        self.master_cb.setStyleSheet("font-size:14px;font-weight:bold;color:#c0392b;")
        self.master_cb.setChecked(False)
        self.btn_detect = QPushButton("🔍 检测游戏窗口")
        self.btn_save = QPushButton("💾 保存配置")
        self.btn_load = QPushButton("📂 重载配置")
        top.addWidget(self.master_cb)
        top.addStretch()
        top.addWidget(self.btn_detect)
        top.addWidget(self.btn_load)
        top.addWidget(self.btn_save)
        lay.addLayout(top)

        kw = QHBoxLayout()
        kw.addWidget(QLabel("窗口标题关键词:"))
        self.kw_edit = QLineEdit(self.config['window_keywords'])
        kw.addWidget(self.kw_edit)
        lay.addLayout(kw)

        self.tabs = QTabWidget()
        lay.addWidget(self.tabs)
        self._create_buff_tab()
        self._create_attack_tab()

        lay.addWidget(QLabel("运行日志："))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(150)
        lay.addWidget(self.log_text)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_label = QLabel("状态: 未启用")
        sb.addWidget(self.status_label)

    def _create_buff_tab(self):
        t = QWidget()
        v = QVBoxLayout(t)
        r0 = QHBoxLayout()
        self.buffs_enabled_cb = QCheckBox("启用上 Buff（独立开关）")
        self.buffs_enabled_cb.setChecked(True)
        self.buffs_enabled_cb.setStyleSheet("font-weight:bold;color:#2c7a2c;")
        r0.addWidget(self.buffs_enabled_cb)
        r0.addStretch()
        v.addLayout(r0)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Buff 之间间隔:"))
        self.buff_interval_spin = QDoubleSpinBox()
        self.buff_interval_spin.setRange(0.1, 20.0)
        self.buff_interval_spin.setValue(1.0)
        self.buff_interval_spin.setSingleStep(0.1)
        self.buff_interval_spin.setSuffix(" 秒")
        r1.addWidget(self.buff_interval_spin)
        self.pause_attack_cb = QCheckBox("上 Buff 时暂停攻击（推荐）")
        self.pause_attack_cb.setChecked(True)
        r1.addWidget(self.pause_attack_cb)
        r1.addStretch()
        v.addLayout(r1)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["启用", "名称", "按键", "间隔(秒)", "倒计时"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(28)
        self.table.doubleClicked.connect(lambda _: self._edit_buff())
        v.addWidget(self.table)

        bl = QHBoxLayout()
        self.btn_add = QPushButton("➕ 添加")
        self.btn_edit = QPushButton("✏️ 编辑")
        self.btn_del = QPushButton("🗑 删除")
        self.btn_up = QPushButton("⬆ 上移")
        self.btn_down = QPushButton("⬇ 下移")
        for b in [self.btn_add, self.btn_edit, self.btn_del, self.btn_up, self.btn_down]:
            bl.addWidget(b)
        bl.addStretch()
        v.addLayout(bl)
        self.tabs.addTab(t, "🧪 Buff")

    def _create_attack_tab(self):
        t = QWidget()
        f = QFormLayout(t)
        self.attack_enabled_cb = QCheckBox("启用自动攻击（独立开关）")
        self.attack_enabled_cb.setChecked(False)
        self.attack_enabled_cb.setStyleSheet("font-weight:bold;color:#c0392b;")

        self.attack_direction_cb = QComboBox()
        for d in DIRECTION_KEYS:
            self.attack_direction_cb.addItem(f"{DIRECTION_CN[d]}  ({d})", d)

        self.attack_key_cb = QComboBox()
        self.attack_key_cb.addItems(KEY_OPTIONS)
        idx = self.attack_key_cb.findText('ctrl')
        if idx >= 0:
            self.attack_key_cb.setCurrentIndex(idx)

        self.attack_mode_cb = QComboBox()
        for key, name in ATTACK_MODES:
            self.attack_mode_cb.addItem(name, key)

        self.jump_key_cb = QComboBox()
        self.jump_key_cb.addItems(KEY_OPTIONS)
        idx = self.jump_key_cb.findText('alt')
        if idx >= 0:
            self.jump_key_cb.setCurrentIndex(idx)

        self.jump_cycle_spin = QDoubleSpinBox()
        self.jump_cycle_spin.setRange(0.4, 3.0)
        self.jump_cycle_spin.setValue(0.70)
        self.jump_cycle_spin.setSingleStep(0.05)
        self.jump_cycle_spin.setSuffix(" 秒")

        self.jump_atk_delay_spin = QDoubleSpinBox()
        self.jump_atk_delay_spin.setRange(0.01, 0.5)
        self.jump_atk_delay_spin.setValue(0.05)
        self.jump_atk_delay_spin.setSingleStep(0.01)
        self.jump_atk_delay_spin.setSuffix(" 秒")

        self.jump_atk_hold_spin = QDoubleSpinBox()
        self.jump_atk_hold_spin.setRange(0.02, 0.5)
        self.jump_atk_hold_spin.setValue(0.10)
        self.jump_atk_hold_spin.setSingleStep(0.02)
        self.jump_atk_hold_spin.setSuffix(" 秒")

        # 巡逻
        self.patrol_change_spin = QDoubleSpinBox()
        self.patrol_change_spin.setRange(1.0, 120.0)
        self.patrol_change_spin.setValue(8.0)
        self.patrol_change_spin.setSingleStep(1.0)
        self.patrol_change_spin.setSuffix(" 秒")

        self.patrol_turn_delay_spin = QDoubleSpinBox()
        self.patrol_turn_delay_spin.setRange(0.0, 30.0)
        self.patrol_turn_delay_spin.setValue(2.0)
        self.patrol_turn_delay_spin.setSingleStep(0.5)
        self.patrol_turn_delay_spin.setSuffix(" 秒")

        # ★ 鼠标模式
        self.patrol_use_mouse_cb = QCheckBox(
            "★ 鼠标控制方向（鼠标左→左走，鼠标右→右走，鼠标中→停）"
        )
        self.patrol_use_mouse_cb.setChecked(False)

        self.mouse_deadzone_spin = QDoubleSpinBox()
        self.mouse_deadzone_spin.setRange(0.0, 0.9)
        self.mouse_deadzone_spin.setValue(0.20)
        self.mouse_deadzone_spin.setSingleStep(0.05)
        self.mouse_deadzone_spin.setDecimals(2)
        self.mouse_deadzone_spin.setSuffix("（比例）")

        # 步进
        self.step_mode_cb = QComboBox()
        for key, name in STEP_MODES:
            self.step_mode_cb.addItem(name, key)

        self.step_interval_spin = QDoubleSpinBox()
        self.step_interval_spin.setRange(5, 3600)
        self.step_interval_spin.setValue(60)
        self.step_interval_spin.setSingleStep(5)
        self.step_interval_spin.setSuffix(" 秒")

        self.step_forward_spin = QDoubleSpinBox()
        self.step_forward_spin.setRange(0.1, 30)
        self.step_forward_spin.setValue(1.5)
        self.step_forward_spin.setSingleStep(0.1)
        self.step_forward_spin.setSuffix(" 秒")

        self.step_attack_spin = QDoubleSpinBox()
        self.step_attack_spin.setRange(0.05, 30)
        self.step_attack_spin.setValue(0.3)
        self.step_attack_spin.setSingleStep(0.05)
        self.step_attack_spin.setSuffix(" 秒")

        self.step_backward_spin = QDoubleSpinBox()
        self.step_backward_spin.setRange(0.1, 30)
        self.step_backward_spin.setValue(1.5)
        self.step_backward_spin.setSingleStep(0.1)
        self.step_backward_spin.setSuffix(" 秒")

        self.turn_hold_spin = QDoubleSpinBox()
        self.turn_hold_spin.setRange(0.02, 0.5)
        self.turn_hold_spin.setValue(0.06)
        self.turn_hold_spin.setSingleStep(0.01)
        self.turn_hold_spin.setSuffix(" 秒")

        f.addRow("", self.attack_enabled_cb)
        f.addRow("初始方向", self.attack_direction_cb)
        f.addRow("攻击键", self.attack_key_cb)
        f.addRow("★ 攻击模式", self.attack_mode_cb)
        f.addRow("跳跃键", self.jump_key_cb)
        f.addRow("跳跃总周期", self.jump_cycle_spin)
        f.addRow("跳跃后多久按攻击", self.jump_atk_delay_spin)
        f.addRow("攻击键按住时长", self.jump_atk_hold_spin)

        f.addRow("—— 巡逻跳跃（标飞）——", QLabel(""))
        f.addRow("", self.patrol_use_mouse_cb)
        f.addRow("★ 鼠标中区比例", self.mouse_deadzone_spin)
        f.addRow("（鼠标模式关闭时↓生效）", QLabel(""))
        f.addRow("巡逻换向间隔", self.patrol_change_spin)
        f.addRow("★ 巡逻转向延迟", self.patrol_turn_delay_spin)

        f.addRow("—— 步进 ——", QLabel(""))
        f.addRow("★ 步进模式", self.step_mode_cb)
        f.addRow("步进间隔", self.step_interval_spin)
        f.addRow("前进时长", self.step_forward_spin)
        f.addRow("攻击时长", self.step_attack_spin)
        f.addRow("返回时长", self.step_backward_spin)
        f.addRow("★ 转向按住时长", self.turn_hold_spin)

        info = QLabel(
            "【鼠标控制方向】\n"
            "  • 勾选后：鼠标在游戏窗口左半边 → 往左走；右半边 → 往右走\n"
            "  • 鼠标在中间区域 → 松开方向键原地跳（不移动）\n"
            "  • 中区比例 0.20 = 中间 20% 宽度为死区（停止）\n"
            "  • 鼠标在窗口外也会被识别为停止\n"
            "  • 勾选后，巡逻换向间隔 / 巡逻转向延迟失效\n\n"
            "【步进模式说明】\n"
            "  • 关：不步进\n"
            "  • 回头模式：往后走一下打一下再回来，保持原朝向\n"
            "  • 前进模式：前进 → 攻击 → 返回 → 转向"
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#2d8cf0;font-size:11px;")
        f.addRow(info)
        self.tabs.addTab(t, "⚔ 攻击")

    def _connect_signals(self):
        self.signals.log.connect(self._log)
        self.signals.state.connect(lambda s: self.status_label.setText(f"状态: {s}"))

        self.master_cb.toggled.connect(self._on_master_toggled)
        self.btn_add.clicked.connect(self._add_buff)
        self.btn_edit.clicked.connect(self._edit_buff)
        self.btn_del.clicked.connect(self._del_buff)
        self.btn_up.clicked.connect(lambda: self._move_buff(-1))
        self.btn_down.clicked.connect(lambda: self._move_buff(1))
        self.btn_detect.clicked.connect(self._on_detect)
        self.btn_save.clicked.connect(self._save_config)
        self.btn_load.clicked.connect(self._on_load)
        self.kw_edit.editingFinished.connect(self._on_kw_changed)
        self.table.itemChanged.connect(self._on_table_item_changed)

        self.buffs_enabled_cb.toggled.connect(
            lambda v: self.config.__setitem__('buffs_enabled', bool(v)))
        self.pause_attack_cb.toggled.connect(
            lambda v: self.config.__setitem__('pause_attack_on_buff', bool(v)))
        self.buff_interval_spin.valueChanged.connect(
            lambda v: self.config.__setitem__('buff_interval', float(v)))

        self.attack_enabled_cb.toggled.connect(self._on_attack_enabled_toggled)
        self.attack_direction_cb.currentIndexChanged.connect(self._on_attack_dir_changed)
        self.attack_key_cb.currentTextChanged.connect(
            lambda s: self.config['attack'].__setitem__('key', s.strip().lower()))
        self.attack_mode_cb.currentIndexChanged.connect(self._on_attack_mode_changed)
        self.jump_key_cb.currentTextChanged.connect(
            lambda s: self.config['attack'].__setitem__('jump_key', s.strip().lower()))
        self.jump_cycle_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('jump_cycle_ms', int(v * 1000)))
        self.jump_atk_delay_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('jump_atk_delay_ms', int(v * 1000)))
        self.jump_atk_hold_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('jump_atk_hold_ms', int(v * 1000)))
        self.patrol_change_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('patrol_change_interval', float(v)))
        self.patrol_turn_delay_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('patrol_turn_delay', float(v)))
        self.patrol_use_mouse_cb.toggled.connect(
            lambda v: self.config['attack'].__setitem__('patrol_use_mouse', bool(v)))
        self.mouse_deadzone_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('mouse_deadzone', float(v)))
        self.step_mode_cb.currentIndexChanged.connect(self._on_step_mode_changed)
        self.step_interval_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('step_interval', float(v)))
        self.step_forward_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('step_forward', float(v)))
        self.step_attack_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('step_attack', float(v)))
        self.step_backward_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('step_backward', float(v)))
        self.turn_hold_spin.valueChanged.connect(
            lambda v: self.config['attack'].__setitem__('turn_hold', float(v)))

    def _on_kw_changed(self):
        self.config['window_keywords'] = self.kw_edit.text().strip()

    def _on_attack_enabled_toggled(self, v):
        self.config['attack']['enabled'] = bool(v)
        if v and not self.bot.game_window:
            self.bot.find_window()

    def _on_attack_dir_changed(self, idx):
        d = self.attack_direction_cb.itemData(idx)
        if d:
            self.config['attack']['direction'] = d

    def _on_attack_mode_changed(self, idx):
        m = self.attack_mode_cb.itemData(idx)
        if m:
            self.config['attack']['mode'] = m

    def _on_step_mode_changed(self, idx):
        m = self.step_mode_cb.itemData(idx)
        if m:
            self.config['attack']['step_mode'] = m

    def _sync_ui_from_config(self):
        a = self.config['attack']
        self.attack_enabled_cb.setChecked(bool(a.get('enabled', False)))
        d = a.get('direction', 'right')
        for i in range(self.attack_direction_cb.count()):
            if self.attack_direction_cb.itemData(i) == d:
                self.attack_direction_cb.setCurrentIndex(i)
                break
        k = a.get('key', 'ctrl')
        idx = self.attack_key_cb.findText(k)
        if idx >= 0:
            self.attack_key_cb.setCurrentIndex(idx)
        m = a.get('mode', 'hold')
        for i in range(self.attack_mode_cb.count()):
            if self.attack_mode_cb.itemData(i) == m:
                self.attack_mode_cb.setCurrentIndex(i)
                break
        jk = a.get('jump_key', 'alt')
        idx = self.jump_key_cb.findText(jk)
        if idx >= 0:
            self.jump_key_cb.setCurrentIndex(idx)
        self.jump_cycle_spin.setValue(int(a.get('jump_cycle_ms', 700)) / 1000.0)
        self.jump_atk_delay_spin.setValue(int(a.get('jump_atk_delay_ms', 50)) / 1000.0)
        self.jump_atk_hold_spin.setValue(int(a.get('jump_atk_hold_ms', 100)) / 1000.0)
        self.patrol_change_spin.setValue(float(a.get('patrol_change_interval', 8.0)))
        self.patrol_turn_delay_spin.setValue(float(a.get('patrol_turn_delay', 0.0)))
        self.patrol_use_mouse_cb.setChecked(bool(a.get('patrol_use_mouse', False)))
        self.mouse_deadzone_spin.setValue(float(a.get('mouse_deadzone', 0.20)))

        sm = a.get('step_mode', 'off')
        for i in range(self.step_mode_cb.count()):
            if self.step_mode_cb.itemData(i) == sm:
                self.step_mode_cb.setCurrentIndex(i)
                break

        self.step_interval_spin.setValue(float(a.get('step_interval', 60)))
        self.step_forward_spin.setValue(float(a.get('step_forward', 1.5)))
        self.step_attack_spin.setValue(float(a.get('step_attack', 0.3)))
        self.step_backward_spin.setValue(float(a.get('step_backward', 1.5)))
        self.turn_hold_spin.setValue(float(a.get('turn_hold', 0.06)))

        self.buffs_enabled_cb.setChecked(bool(self.config.get('buffs_enabled', True)))
        self.pause_attack_cb.setChecked(bool(self.config.get('pause_attack_on_buff', True)))
        self.buff_interval_spin.setValue(float(self.config.get('buff_interval', 1.0)))

    def _rebuild_table(self):
        self._updating_table = True
        self.table.setRowCount(0)
        for buff in self.config.get('buffs', []):
            self._append_row(buff)
        self._updating_table = False

    def _append_row(self, buff):
        row = self.table.rowCount()
        self.table.insertRow(row)
        chk = QTableWidgetItem()
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        chk.setCheckState(Qt.Checked if buff.get('enabled', True) else Qt.Unchecked)
        chk.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 0, chk)
        name = QTableWidgetItem(buff.get('name', ''))
        name.setData(Qt.UserRole, buff.get('id'))
        self.table.setItem(row, 1, name)
        keys = QTableWidgetItem(buff.get('keys_str', ''))
        keys.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 2, keys)
        iv = QTableWidgetItem(f"{float(buff.get('interval', 180)):.0f}")
        iv.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 3, iv)
        cd = QTableWidgetItem("--")
        cd.setTextAlignment(Qt.AlignCenter)
        self.table.setItem(row, 4, cd)

    def _find_buff_by_id(self, bid):
        if bid is None:
            return None
        for b in self.config.get('buffs', []):
            if b.get('id') == bid:
                return b
        return None

    def _current_row_buff(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        name_item = self.table.item(row, 1)
        if not name_item:
            return None
        return self._find_buff_by_id(name_item.data(Qt.UserRole))

    def _on_table_item_changed(self, item):
        if self._updating_table:
            return
        if item.column() != 0:
            return
        row = item.row()
        name_item = self.table.item(row, 1)
        if not name_item:
            return
        buff = self._find_buff_by_id(name_item.data(Qt.UserRole))
        if buff is None:
            return
        buff['enabled'] = (item.checkState() == Qt.Checked)

    def _add_buff(self):
        dlg = BuffDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        buff = dlg.get_buff()
        buff['id'] = uuid.uuid4().hex
        self.config.setdefault('buffs', []).append(buff)
        self._rebuild_table()
        self._log(f"[+] 已添加 Buff: {buff['name']} ({buff['keys_str']}, {buff['interval']:.0f}s)")

    def _edit_buff(self):
        buff = self._current_row_buff()
        if buff is None:
            QMessageBox.information(self, "提示", "请先选中一行 Buff")
            return
        dlg = BuffDialog(self, buff)
        if dlg.exec_() != QDialog.Accepted:
            return
        buff.update(dlg.get_buff())
        self.bot.last_cast.pop(buff.get('id'), None)
        self._rebuild_table()
        self._log(f"[✏] 已修改 Buff: {buff['name']}")

    def _del_buff(self):
        buff = self._current_row_buff()
        if buff is None:
            QMessageBox.information(self, "提示", "请先选中一行 Buff")
            return
        if QMessageBox.question(self, "确认", f"删除 Buff「{buff['name']}」？") != QMessageBox.Yes:
            return
        self.config['buffs'].remove(buff)
        self.bot.last_cast.pop(buff.get('id'), None)
        self._rebuild_table()
        self._log(f"[-] 已删除 Buff: {buff['name']}")

    def _move_buff(self, delta):
        buff = self._current_row_buff()
        if buff is None:
            return
        buffs = self.config.get('buffs', [])
        ids = [b.get('id') for b in buffs]
        try:
            i = ids.index(buff.get('id'))
        except ValueError:
            return
        j = i + delta
        if j < 0 or j >= len(buffs):
            return
        buffs[i], buffs[j] = buffs[j], buffs[i]
        self._rebuild_table()
        self.table.selectRow(j)

    def _on_master_toggled(self, checked):
        if checked and not self.bot.game_window:
            self.bot.find_window()
        self.bot.set_master(checked)
        self.status_label.setText("状态: " + ("运行中" if checked else "未启用"))

    def _on_detect(self):
        if self.bot.find_window():
            QMessageBox.information(self, "成功", f"已找到窗口：{self.bot.game_window['title']}")
        else:
            QMessageBox.warning(self, "失败", "未找到游戏窗口，请检查窗口标题关键词")

    def _tick(self):
        now = time.time()
        buff_interval = float(self.config.get('buff_interval', 1.0))
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 1)
            if not name_item:
                continue
            buff = self._find_buff_by_id(name_item.data(Qt.UserRole))
            if not buff:
                continue
            cd_item = self.table.item(row, 4)
            if not cd_item:
                continue
            if not buff.get('enabled', True):
                cd_item.setText("已禁用")
                continue
            if not self.config.get('buffs_enabled', True):
                cd_item.setText("总Buff关")
                continue
            if not self.bot.master_enabled:
                cd_item.setText("总开关关")
                continue
            iv = float(buff.get('interval', 180))
            last = self.bot.last_cast.get(buff.get('id'), 0)
            if last == 0:
                cd_item.setText("待触发")
            else:
                remain = max(0.0, iv - (now - last))
                gap = buff_interval - (now - self.bot._last_any_cast)
                if remain <= 0 and gap > 0:
                    cd_item.setText(f"冷却{gap:.1f}s")
                else:
                    cd_item.setText(f"{remain:.1f}s")

        f8 = (user32.GetAsyncKeyState(0x77) & 0x8000) != 0
        if f8 and not self._f8_prev:
            self.master_cb.setChecked(not self.master_cb.isChecked())
        self._f8_prev = f8
        f9 = (user32.GetAsyncKeyState(0x78) & 0x8000) != 0
        if f9 and not self._f9_prev:
            self.master_cb.setChecked(False)
            self._log("[F9] 总开关已关闭")
        self._f9_prev = f9

    def _log(self, m):
        self.log_text.append(m)
        self.log_text.verticalScrollBar().setValue(self.log_text.verticalScrollBar().maximum())

    def _config_path(self):
        base = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
        return base / "buff_config.json"

    def _save_config(self):
        self.config['master_enabled'] = self.master_cb.isChecked()
        self.config['window_keywords'] = self.kw_edit.text().strip() or 'MapleStory,冒险岛怀旧服'
        path = self._config_path()
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            self._log(f"[√] 配置已保存：{path.name}")
        except Exception as e:
            self._log(f"[!] 保存失败：{e}")

    def _load_config(self):
        path = self._config_path()
        if not path.exists():
            self._log(f"[i] 配置文件不存在，使用默认配置：{path.name}")
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            self.config['window_keywords'] = cfg.get('window_keywords', self.config['window_keywords'])
            self.config['buff_interval'] = float(cfg.get('buff_interval', self.config['buff_interval']))
            self.config['buffs_enabled'] = bool(cfg.get('buffs_enabled', True))
            self.config['pause_attack_on_buff'] = bool(cfg.get('pause_attack_on_buff', True))
            self.config['buffs'] = cfg.get('buffs', [])
            for b in self.config['buffs']:
                if 'id' not in b:
                    b['id'] = uuid.uuid4().hex

            src_atk = dict(cfg.get('attack', {}))
            if 'mode' not in src_atk:
                src_atk['mode'] = 'jump' if src_atk.get('jump_attack', False) else 'hold'
            src_atk.pop('jump_attack', None)
            if 'step_mode' not in src_atk:
                src_atk['step_mode'] = 'forward'

            for k, v in src_atk.items():
                self.config['attack'][k] = v

            self.kw_edit.setText(self.config['window_keywords'])
            self._log(f"[√] 配置已加载：{path.name}（{len(self.config['buffs'])} 个 Buff）")
        except Exception as e:
            self._log(f"[!] 加载配置失败：{e}")

    def _on_load(self):
        self._load_config()
        self._rebuild_table()
        self._sync_ui_from_config()

    def closeEvent(self, e):
        self.bot.shutdown()
        time.sleep(0.2)
        e.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())