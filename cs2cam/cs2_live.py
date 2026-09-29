#!/usr/bin/env python3
"""
CS2 PPPP live-view client for the CY365 / 365Cam camera family (device ID
prefix EEE), e.g. EEE-304142-PYVFU.

Rewritten after finding the root cause of the "stream not decoded / often not
sent at all" problem: the effective encryption key was wrong in 2 of its 4
bytes (3cc4662e instead of 3cc4680a). That single error explains every
"oddity" noted in the previous version:

  * all cmd bytes looked XOR 0x0E shifted (0xDE instead of 0xD0 = Drw,
    0xEE instead of 0xE0 = P2PAlive, 0x4C instead of 0x42 = P2pRdy, ...),
  * the length field looked "unreliable" (P2PAlive is really f1 e0 00 00,
    not f1 ee 00 9e),
  * no H.264 start codes / "mystery sub-headers" in the video data -- about
    half of every payload byte was decrypted wrongly,
  * every packet the script BUILT ITSELF (JSON login, stream request,
    DrwAcks, LAN search) arrived at the camera as garbage, so only verbatim
    replays from the app capture had any effect. Replays carry stale
    cmd_idx values, so the camera treated later fresh commands with the
    same idx as duplicates.

With the corrected key every packet from the app capture decrypts to clean
plaintext, e.g.
    f1 d0 0056 | d1 00 0000 | 060aa080 4a000000 {"pro":"check_user",...}
    f1 d0 00d9 | d1 00 0004 | ... {"pro":"stream","cmd":111,"video":1,"camsmode":0,...}
    f1 41 0014 | "EEE" 00.. | 0004a40e | "PYVFU" 00..   (PunchPkt)
Run  `python3 cs2_live.py --selftest`  to verify this offline.

Protocol (standard CS2 PPPP, see also devbis/aiopppp):
    outer header   f1 <type> <len16 BE>              (len = bytes after it)
    Drw     0xd0   d1 <channel> <idx16 BE> <payload>
    DrwAck  0xd1   d1 <channel> <count16> <idx16>*count
    channels: 0 = JSON commands/replies, 1 = video, 2 = audio
    JSON record in a Drw payload: 06 0a a0 80 <len32 LE> <json>
    video: a frame starts with a Drw whose payload begins with
    55 aa 15 a8 followed by a 32-byte (total) frame header; following Drw
    packets (consecutive idx) carry the rest of the frame.

Requirements: ffplay (from ffmpeg) on PATH for display. The codec (H.264
Annex-B or MJPEG) is detected from the first complete frame.
"""

import argparse
import json
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CAMERA_IP = "192.168.10.1"     # camera's own AP gateway IP
DISCOVERY_PORT = 32108         # fixed LAN-search port
DEVICE_ID = "EEE-304142-PYVFU"
USERNAME = "admin"
PASSWORD = "6666"
DEBUG = True
DEBUG_CMD_CHANNEL = False      # log every raw channel-0 (command) packet
FORCE_STREAM_CMD = False       # send 'stream' even if video already flows
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

KEEPALIVE_INTERVAL = 1.0       # our own P2PAlive
RESEND_INTERVAL = 0.5          # resend un-acked outgoing Drw packets
HEART_INTERVAL = 0             # 0 = off. The app sends heart once; repeating it
                               # every 10 s coincided with the camera stalling          # app sends dev_control/heart; repeated here
                               # as a stream keep-alive (semantics unconfirmed)

# ---------------------------------------------------------------------------
# Crypto (CS2 "P2P_Proprietary" CFB-style cipher)
# ---------------------------------------------------------------------------

TABLE = bytes.fromhex(
    "7c9ce84a13dedcb22f2123e4307b3d8cbc0b270c3cf79ae7087196009785efc1"
    "1fc4dba1c2ebd901faba3b05b81587832872d18b5ad6da9358feaacc6e1bf0a3"
    "88ab43c00db545384f502266207f075b14981d9ba72ab9a8cbf1fc4947063eb1"
    "0e043a945eee541134dd4df9ecc7c9e3781a6f706ba4bda95dd5f8e5bb26af42"
    "37d8e1020aae5f1cc573094e6924906d12b319ad748a2940f52dbea559e0f479"
    "d24bce8982488425c6912ba2fb8fe9a6b09e3f65f603312eac0f952c5ced39b7"
    "336c567eb4a0fd7a815351868d9f77ff6a80dfe2bf10d775645776f355cdd0c8"
    "18e6364162cf99f2324c67606192cad3ea637d16b68ed46835c3529d46441e17"
)
assert len(TABLE) == 256

# Effective 4-byte key (output of the app's key derivation). Solved from
# the app capture: it is the only value for which all captured packets
# decrypt to valid PPPP headers and plain-ASCII JSON. The previous script's
# SESSION_KEY 3103331d2f1a340635 derives to 3cc4662e -- bytes 2 and 3 wrong.
EFFECTIVE_KEY = bytes.fromhex("3cc4680a")


def _ks(ek, prev):
    return TABLE[(prev + ek[prev & 3]) & 0xff]


def cs2_decrypt(data, ek=EFFECTIVE_KEY):
    if not data:
        return b""
    out = bytearray(len(data))
    out[0] = data[0] ^ TABLE[ek[0]]
    for i in range(1, len(data)):
        out[i] = data[i] ^ _ks(ek, data[i - 1])
    return bytes(out)


def cs2_encrypt(data, ek=EFFECTIVE_KEY):
    if not data:
        return b""
    out = bytearray(len(data))
    out[0] = data[0] ^ TABLE[ek[0]]
    for i in range(1, len(data)):
        out[i] = data[i] ^ _ks(ek, out[i - 1])
    return bytes(out)


# ---------------------------------------------------------------------------
# Packets
# ---------------------------------------------------------------------------

MAGIC = 0xf1
T_LAN_SEARCH = 0x30
T_PUNCH = 0x41
T_P2P_RDY = 0x42
T_DRW = 0xd0
T_DRW_ACK = 0xd1
T_ALIVE = 0xe0
T_ALIVE_ACK = 0xe1
T_CLOSE = 0xf0

CH_CMD = 0
CH_VIDEO = 1
CH_AUDIO = 2

JSON_PREAMBLE = bytes.fromhex("060aa080")   # camera replies may use 06 0a a1 80;
                                            # only 06 0a is fixed (as in aiopppp)

# JSON command numbers (devbis/aiopppp const.py JsonCommands)
CMD_SET_CYPUSH = 1
CMD_CHECK_USER = 100
CMD_GET_PARMS = 101
CMD_DEV_CONTROL = 102       # lamp=0/1, icut=0/1, heart=1, reboot=1
CMD_GET_ALARM = 107
CMD_SET_ALARM = 108
CMD_STREAM = 111
CMD_SET_DATETIME = 126
CMD_PTZ_CONTROL = 128
CMD_SET_WHITELIGHT = 304    # status=0/1
CMD_GET_WHITELIGHT = 305
JSON_NAMES = {
    CMD_SET_CYPUSH: "set_cypush", CMD_CHECK_USER: "check_user",
    CMD_GET_PARMS: "get_parms", CMD_DEV_CONTROL: "dev_control",
    CMD_GET_ALARM: "get_alarm", CMD_SET_ALARM: "set_alarm",
    CMD_STREAM: "stream", CMD_SET_DATETIME: "set_datetime",
    CMD_PTZ_CONTROL: "ptz_control", CMD_SET_WHITELIGHT: "set_whiteLight",
    CMD_GET_WHITELIGHT: "get_whiteLight",
}
PUSH_PORT = 9093            # port the official app configures via set_cypush

HELP = """commands (type + Enter while streaming):
  led on|off           status LED            (dev_control lamp=1/0)
  ir on|off|toggle     infrared night mode   (dev_control icut=1/0)
  ir <n>               raw icut value (e.g. 2 -- camera reports isShowIcutAuto)
  light on|off         white light, if any   (set_whiteLight status=1/0)
  parms                read camera parameters (get_parms) -- may block camera ~40 s
  alarm                read motion-alarm settings (get_alarm)
  raw {json}           send any JSON command, e.g. raw {"pro":"get_alarm","cmd":107}
  stream               (re)request the video stream
  reboot               reboot camera
  help"""
VIDEO_MARKER = b"\x55\xaa\x15\xa8"
VIDEO_HEADER_LEN = 0x20


def pkt(ptype, payload=b""):
    return struct.pack(">BBH", MAGIC, ptype, len(payload)) + payload


def parse_device_id(dev_id):
    prefix, serial, suffix = dev_id.split("-")
    return prefix.encode(), int(serial), suffix.encode()


def make_punch(dev_id=DEVICE_ID):
    prefix, serial, suffix = parse_device_id(dev_id)
    return pkt(T_PUNCH, prefix.ljust(8, b"\0") + struct.pack(">I", serial)
               + suffix.ljust(8, b"\0"))


def make_drw(channel, idx, payload):
    return pkt(T_DRW, struct.pack(">BBH", 0xd1, channel, idx) + payload)


def make_drw_ack(channel, idxs):
    body = struct.pack(">BBH", 0xd1, channel, len(idxs))
    body += b"".join(struct.pack(">H", i) for i in idxs)
    return pkt(T_DRW_ACK, body)


def json_record(obj):
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return JSON_PREAMBLE + struct.pack("<I", len(raw)) + raw


def parse_json_records(payload, keep_partial=False):
    """Returns the JSON records in `payload`. With keep_partial=True returns
    (records, rest) where `rest` is an incomplete trailing record -- long
    replies are split over several Drw packets on channel 0."""
    out, pos = [], 0
    while pos + 8 <= len(payload):
        if payload[pos:pos + 2] != JSON_PREAMBLE[:2]:
            nxt = payload.find(JSON_PREAMBLE[:2], pos + 1)
            if nxt < 0:
                log("skipping non-JSON channel-0 data:", payload[pos:pos + 48].hex())
                pos = len(payload)
                break
            pos = nxt
            continue
        n = struct.unpack("<I", payload[pos + 4:pos + 8])[0]
        if pos + 8 + n > len(payload) and keep_partial:
            break
        raw = payload[pos + 8:pos + 8 + n]
        pos += 8 + n
        try:
            out.append(json.loads(raw.rstrip(b"\0").decode("utf-8", "replace")))
        except ValueError:
            out.append({"_raw": raw.hex()})
    if keep_partial:
        return out, payload[pos:]
    return out


def log(*args):
    if DEBUG:
        print(f"[{time.strftime('%H:%M:%S')}]", *args, flush=True)


# ---------------------------------------------------------------------------
# Video frame assembly
# ---------------------------------------------------------------------------

class Unwrapper:
    """Turns wrapping 16-bit Drw indices into a monotonic counter."""

    def __init__(self):
        self.last = None

    def __call__(self, idx):
        if self.last is None:
            self.last = idx
            return idx
        diff = (idx - (self.last & 0xffff) + 0x8000) % 0x10000 - 0x8000
        value = self.last + diff
        self.last = max(self.last, value)
        return value


class FrameAssembler:
    """Collects channel-1 Drw payloads and emits complete frames.

    A frame = boundary packet (payload starts with 55aa15a8, 32-byte header
    stripped) + all following idx up to the next boundary. The camera
    retransmits until acked, so gaps are usually filled; a frame that is
    still incomplete when a third boundary arrives is dropped.
    """

    def __init__(self):
        self.unwrap = Unwrapper()
        self.chunks = {}
        self.headers = {}
        self.boundaries = []
        self.done_before = None

    def feed(self, idx, payload):
        u = self.unwrap(idx)
        if self.done_before is not None and u < self.done_before:
            return []
        if u in self.chunks:
            return []
        if payload.startswith(VIDEO_MARKER):
            self.headers[u] = payload[:VIDEO_HEADER_LEN]
            payload = payload[VIDEO_HEADER_LEN:]
            self.boundaries.append(u)
            self.boundaries.sort()
        self.chunks[u] = payload
        return self._emit()

    def _emit(self):
        frames = []
        while len(self.boundaries) >= 2:
            a, b = self.boundaries[0], self.boundaries[1]
            missing = [i for i in range(a, b) if i not in self.chunks]
            if missing and len(self.boundaries) < 3:
                break
            if missing:
                log(f"dropping frame {a}..{b - 1}: {len(missing)} chunks missing")
            else:
                frames.append((self.headers.get(a, b""),
                               b"".join(self.chunks[i] for i in range(a, b))))
            self.boundaries.pop(0)
            self.done_before = b
            for i in [i for i in self.chunks if i < b]:
                del self.chunks[i]
            for i in [i for i in self.headers if i < b]:
                del self.headers[i]
        return frames


def detect_codec(frame):
    head = frame[:64]
    if head.startswith(b"\xff\xd8"):
        return "mjpeg"
    if b"\x00\x00\x00\x01" in head or head.startswith(b"\x00\x00\x01"):
        return "h264"
    return None


class Player:
    """Starts ffplay lazily once the codec is known; writes via a thread so
    a slow ffplay can never stall the network loop."""

    def __init__(self):
        self.proc = None
        self.codec = None
        self.q = queue.Queue(maxsize=300)
        self.dump = None

    def push(self, frame):
        if self.codec is None:
            self.codec = detect_codec(frame)
            if self.codec is None:
                log("unknown frame format, first bytes:", frame[:48].hex())
                return
            path = os.path.join(OUT_DIR, "stream_dump." + self.codec)
            self.dump = open(path, "wb")
            log(f"codec detected: {self.codec}, dumping to {path}")
            try:
                self.proc = subprocess.Popen(
                    ["ffplay", "-f", self.codec, "-fflags", "nobuffer",
                     "-flags", "low_delay", "-framedrop", "-loglevel", "warning",
                     "-window_title", "CS2 Camera - Live", "-i", "pipe:0"],
                    stdin=subprocess.PIPE)
                threading.Thread(target=self._writer, daemon=True).start()
            except FileNotFoundError:
                log("ffplay not found -- only dumping to file")
        self.dump.write(frame)
        self.dump.flush()
        if self.proc:
            try:
                self.q.put_nowait(frame)
            except queue.Full:
                log("ffplay falling behind, frame dropped")

    def _writer(self):
        while True:
            item = self.q.get()
            if item is None:
                break
            try:
                self.proc.stdin.write(item)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError):
                break

    def exited(self):
        return self.proc is not None and self.proc.poll() is not None

    def close(self):
        if self.dump:
            self.dump.close()
        if self.proc:
            self.q.put(None)
            try:
                self.proc.stdin.close()
            except OSError:
                pass
            self.proc.wait()


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

def _port_cache():
    return os.path.join(OUT_DIR, ".last_session_port")


def save_port(port):
    try:
        with open(_port_cache(), "w") as f:
            f.write(f"{CAMERA_IP} {port}")
    except OSError:
        pass


def load_port():
    try:
        with open(_port_cache()) as f:
            ip, port = f.read().split()
        return int(port) if ip == CAMERA_IP else None
    except (OSError, ValueError):
        return None

if sys.platform == "win32":
    import ctypes

    def disable_udp_connreset(sock):
        SIO_UDP_CONNRESET = 0x9800000C
        enable = ctypes.c_ulong(0)
        ret_len = ctypes.c_ulong(0)
        ctypes.windll.ws2_32.WSAIoctl(
            sock.fileno(), SIO_UDP_CONNRESET, ctypes.byref(enable),
            ctypes.sizeof(enable), None, 0, ctypes.byref(ret_len), None, None)
else:
    def disable_udp_connreset(sock):
        pass


class Session:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(("0.0.0.0", 0))
        disable_udp_connreset(self.sock)
        self.addr = None
        self.out_idx = 0
        self.unacked = {}           # idx -> (raw packet, last send time)
        self.pending_acks = {}      # channel -> [idx, ...]
        self.assembler = FrameAssembler()
        self.player = Player()
        self.frames = 0
        self.logged_in = False
        self.streaming = False
        self.params = {}            # last get_parms reply
        # cmds we sent and expect a reply to; anything else arriving on
        # channel 0 is reported as an unsolicited EVENT (e.g. motion alarm).
        # set_datetime (126) is answered as cmd 128 (aiopppp const.py).
        self.requested = {CMD_PTZ_CONTROL}
        self.seen_cmd_idx = []      # recent channel-0 idx (camera retransmits)
        self.cmd_buf = b""          # partial JSON record spanning Drw packets
        self.cmd_buf_since = 0
        self.awaiting = {}          # cmd -> [[name, send time, reported], ...] (FIFO)
        self.reply_timeout = 3.0
        self.outq = []
        self.video_requested_at = 0
        self.stream_started = 0              # queued command packets (lists of JSON objs)
        self.last_video = None      # time of the last video packet
        self.console = queue.Queue()
        self.startup_cmds = []      # commands from the command line

    # --- low level -----------------------------------------------------
    def send(self, plain, addr=None):
        self.sock.sendto(cs2_encrypt(plain), addr or self.addr)

    def recv(self, timeout):
        self.sock.settimeout(timeout)
        try:
            data, addr = self.sock.recvfrom(65536)
        except (socket.timeout, ConnectionResetError):
            return None, None
        return cs2_decrypt(data), addr

    # --- connect -------------------------------------------------------
    def connect(self):
        """1. LAN search on 32108 (broadcast + unicast)
        2. PunchPkt to the session port remembered from the last run
        3. PunchPkt to every port 1024-65535 (the camera still answers a
           punch on its session port when it ignores LAN search, e.g. while
           it thinks an old session is alive)"""
        punch = cs2_encrypt(make_punch())
        seen_any = False
        own_port = self.sock.getsockname()[1]

        def listen(seconds):
            nonlocal seen_any
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                dec, addr = self.recv(0.2)
                if not dec:
                    continue
                if addr[1] == own_port and dec == make_punch():
                    continue        # our own scan packet looped back
                if dec[0] != MAGIC:
                    log(f"<- {addr} non-PPPP packet {dec[:16].hex()}")
                    continue
                seen_any = True
                log(f"<- {addr} type=0x{dec[1]:02x} {dec[:24].hex()}")
                if dec[1] in (T_PUNCH, T_P2P_RDY) and self.addr is None:
                    self.addr = addr
                    log(f"camera session endpoint: {addr}")
                    self.sock.sendto(punch, addr)
                if dec[1] == T_P2P_RDY and addr == self.addr:
                    log("P2P ready")
                    save_port(addr[1])
                    return True
                if dec[1] == T_CLOSE:
                    log("camera sent Close -- it may still be busy with an old session")
            return False

        for attempt in range(4):
            for target in ((CAMERA_IP, DISCOVERY_PORT), ("255.255.255.255", DISCOVERY_PORT)):
                try:
                    self.sock.sendto(cs2_encrypt(pkt(T_LAN_SEARCH)), target)
                except OSError as e:
                    log(f"LAN search to {target} failed: {e}")
            if self.addr:
                self.sock.sendto(punch, self.addr)
            if listen(1.0):
                return True

        port = load_port()
        if port and not self.addr:
            log(f"no answer to LAN search, trying last session port {port}")
            for _ in range(3):
                self.sock.sendto(punch, (CAMERA_IP, port))
                if listen(0.7):
                    return True

        if not self.addr:
            print(f"No answer to LAN search -- scanning {CAMERA_IP} ports 1024-65535 ...")
            for p in range(1024, 65536):
                try:
                    self.sock.sendto(punch, (CAMERA_IP, p))
                except OSError:
                    pass
                if p % 4096 == 0 and listen(0.05):
                    return True
        for _ in range(4):
            if self.addr:
                self.sock.sendto(punch, self.addr)
            if listen(1.0):
                return True

        print("\nCamera not found." if not seen_any else
              "\nCamera answered but the P2P handshake did not complete.")
        print(f"""  - Is this PC still connected to the camera's WiFi? (ping {CAMERA_IP})
    Battery cameras switch their WiFi off when idle: press the camera's
    button / move in front of it, or plug it in, then reconnect the WiFi.
  - Close the phone app and any other running instance of this script
    (the camera may accept only one client at a time).
  - Still nothing: power-cycle the camera.""")
        return False

    # --- reliable command channel --------------------------------------
    def send_json(self, *objs):
        """Queue one command packet (one or more JSON records). Packets go
        out one at a time: the next only after the camera acked the previous
        one and answered it (or REPLY_TIMEOUT passed), like aiopppp's
        send_command/wait_ack/wait_cmd_result. Firing several at once made
        the camera's command handling stall."""
        objs = [{**o, "user": USERNAME, "pwd": PASSWORD} for o in objs]
        self.outq.append(objs)
        self.pump()

    def busy(self, now):
        if self.unacked:
            return True
        return any(not e[2] and now - e[1] < self.reply_timeout
                   for entries in self.awaiting.values() for e in entries)

    def pump(self):
        now = time.monotonic()
        if not self.outq or self.busy(now):
            return
        objs = self.outq.pop(0)
        records = b""
        for o in objs:
            self.requested.add(o.get("cmd"))
            args = " ".join(f"{k}={v}" for k, v in o.items()
                            if k not in ("pro", "cmd", "user", "pwd", "time", "tz"))
            label = f"{o.get('pro')} {args}".strip()
            self.awaiting.setdefault(o.get("cmd"), []).append([label, now, False])
            records += json_record(o)
            log("-> JSON", o)
        idx = self.out_idx
        self.out_idx = (self.out_idx + 1) & 0xffff
        raw = make_drw(CH_CMD, idx, records)
        self.unacked[idx] = [raw, now]
        self.send(raw)

    def resend_unacked(self, now):
        """Resend un-acked command packets with backoff (0.5 s .. 2 s).
        Never give up on one: the camera delivers channel 0 strictly in idx
        order, so a skipped idx blocks every later command for good."""
        for idx, entry in self.unacked.items():
            retries = len(entry) - 2
            interval = min(RESEND_INTERVAL * (1.5 ** retries), 2.0)
            if now - entry[1] > interval:
                entry.append(now)
                if retries + 1 == 6:
                    log(f"cmd packet idx={idx} not acked yet -- camera busy, "
                        f"will keep retrying (later commands queue behind it)")
                self.send(entry[0])
                entry[1] = now

    def check_replies(self, now):
        for cmd, entries in list(self.awaiting.items()):
            for entry in entries:
                name, sent, reported = entry
                if not reported and now - sent > self.reply_timeout:
                    entry[2] = True
                    if cmd == CMD_DEV_CONTROL:
                        continue    # often only acked, never answered
                    print(f"[{time.strftime('%H:%M:%S')}] no reply to '{name}' (cmd {cmd}) "
                          f"within {self.reply_timeout:.0f}s (yet)", flush=True)
            # keep entries a while so a late reply can still be matched
            entries[:] = [e for e in entries if now - e[1] < 900]
            if not entries:
                del self.awaiting[cmd]

    def flush_acks(self):
        for ch, idxs in self.pending_acks.items():
            for i in range(0, len(idxs), 64):
                self.send(make_drw_ack(ch, idxs[i:i + 64]))
        self.pending_acks.clear()

    # --- incoming ------------------------------------------------------
    def handle(self, dec):
        if len(dec) < 4 or dec[0] != MAGIC:
            return
        ptype = dec[1]
        body = dec[4:4 + struct.unpack(">H", dec[2:4])[0]]
        if ptype == T_ALIVE:
            self.send(pkt(T_ALIVE_ACK))
        elif ptype == T_DRW and len(body) >= 4:
            _, ch, idx = struct.unpack(">BBH", body[:4])
            self.pending_acks.setdefault(ch, []).append(idx)
            self.on_drw(ch, idx, body[4:])
        elif ptype == T_DRW_ACK and len(body) >= 4:
            _, ch, count = struct.unpack(">BBH", body[:4])
            for k in range(count):
                if 4 + 2 * k + 2 <= len(body):
                    self.unacked.pop(struct.unpack(">H", body[4 + 2 * k:6 + 2 * k])[0], None)
        elif ptype == T_CLOSE:
            raise ConnectionAbortedError("camera closed the session")
        elif ptype in (T_PUNCH, T_P2P_RDY, T_ALIVE_ACK):
            pass
        else:
            log(f"unhandled type 0x{ptype:02x}: {dec[:32].hex()}")

    def on_drw(self, ch, idx, payload):
        if ch == CH_CMD:
            if idx in self.seen_cmd_idx:
                if DEBUG_CMD_CHANNEL:
                    log(f"ch0 idx={idx} retransmitted by camera (our ack got lost?)")
                return
            self.seen_cmd_idx = self.seen_cmd_idx[-63:] + [idx]
            if DEBUG_CMD_CHANNEL:
                log(f"ch0 idx={idx} len={len(payload)} raw:", payload[:64].hex())
            if payload[:2] == JSON_PREAMBLE[:2] and self.cmd_buf:
                # a new record starts -> the buffered one will never complete
                self.flush_partial()
            records, self.cmd_buf = parse_json_records(self.cmd_buf + payload, keep_partial=True)
            if self.cmd_buf:
                self.cmd_buf_since = time.monotonic()
                if DEBUG_CMD_CHANNEL:
                    log(f"holding partial ch0 record ({len(self.cmd_buf)} bytes)")
            for obj in records:
                self.on_json(obj)
        elif ch == CH_VIDEO:
            self.last_video = time.monotonic()
            if payload.startswith(VIDEO_MARKER) and self.frames < 3:
                log("frame header:", payload[:VIDEO_HEADER_LEN].hex(),
                    "data:", payload[VIDEO_HEADER_LEN:VIDEO_HEADER_LEN + 16].hex())
            for header, frame in self.assembler.feed(idx, payload):
                self.frames += 1
                if self.frames % 25 == 1:
                    log(f"frame #{self.frames}: {len(frame)} bytes")
                self.player.push(frame)

    def flush_partial(self):
        """Deliver a buffered record that never completed. Seen causes: a
        length field larger than the data actually sent. Without this, one
        such record swallowed every later reply."""
        buf, self.cmd_buf = self.cmd_buf, b""
        raw = buf[8:].rstrip(b"\0").strip()
        try:
            obj = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            log("dropping incomplete ch0 record:", buf[:64].hex())
            return
        self.on_json(obj)

    def on_json(self, obj):
        cmd = obj.get("cmd")
        pending = self.awaiting.get(CMD_SET_DATETIME if cmd == 128 else cmd)
        if pending:
            name, sent, reported = pending.pop(0)
            delay = time.monotonic() - sent
            if reported or delay > 2.0:
                print(f"[{time.strftime('%H:%M:%S')}] late reply to '{name}' after "
                      f"{delay:.1f}s", flush=True)
        if cmd in self.requested:
            log("<- JSON", obj)
        else:
            # not a reply to anything we asked -- camera-initiated message
            print(f"[{time.strftime('%H:%M:%S')}] *** EVENT from camera: {obj}", flush=True)
        if cmd == CMD_CHECK_USER and not self.logged_in:
            self.logged_in = True
            self.start_stream()
        elif cmd == CMD_GET_PARMS and obj.get("result", 0) == 0:
            self.params.update({k: v for k, v in obj.items() if k not in ("cmd", "result")})
            print("camera parameters:", self.params, flush=True)
        elif "result" in obj and obj["result"] != 0:
            print(f"command {JSON_NAMES.get(cmd, cmd)} failed: {obj}", flush=True)

    # --- camera controls -----------------------------------------------
    def control(self, **kw):
        self.send_json({"pro": "dev_control", "cmd": CMD_DEV_CONTROL, **kw})

    def set_led(self, on):
        self.control(lamp=int(on))
        self.params["lamp"] = int(on)

    def set_ir(self, on):
        self.control(icut=int(on))
        self.params["icut"] = int(on)

    def set_whitelight(self, on):
        self.send_json({"pro": "set_whiteLight", "cmd": CMD_SET_WHITELIGHT, "status": int(on)})

    def do_command(self, line):
        words = line.strip().split(None, 1)
        if not words:
            return
        name, arg = words[0].lower(), (words[1].strip().lower() if len(words) > 1 else "")
        on = {"on": True, "1": True, "an": True, "off": False, "0": False, "aus": False}.get(arg)
        if name == "led" and on is not None:
            self.set_led(on)
        elif name == "ir" and arg.isdigit():
            self.set_ir(int(arg))           # raw icut value, e.g. to find "auto"
        elif name == "ir" and (on is not None or arg == "toggle"):
            if on is None:
                on = not self.params.get("icut", 0)
            self.set_ir(on)
        elif name == "light" and on is not None:
            self.set_whitelight(on)
        elif name == "parms":
            print("note: get_parms can block this camera's command handling for "
                  "40 s or more -- other commands wait until it answers", flush=True)
            self.send_json({"pro": "get_parms", "cmd": CMD_GET_PARMS})
        elif name == "alarm":
            self.send_json({"pro": "get_alarm", "cmd": CMD_GET_ALARM})
        elif name == "pushhere":
            self.push_to_self()
        elif name == "stream":
            self.request_video()
        elif name == "reboot":
            self.control(reboot=1)
        elif name == "raw" and arg:
            try:
                self.send_json(json.loads(words[1]))
            except ValueError as e:
                print("invalid JSON:", e)
        else:
            print(HELP)

    def push_to_self(self):
        """Tell the camera to send its alarm pushes (motion) to this PC.
        The official app sends set_cypush with its cloud server on every
        connect, so the app restores the original target next time it is
        used."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((CAMERA_IP, 1))
        my_ip = probe.getsockname()[0]
        probe.close()
        self.send_json({"pro": "set_cypush", "cmd": CMD_SET_CYPUSH,
                        "pushIp": my_ip, "pushPort": PUSH_PORT, "pushInterval": 180,
                        "cyAdmin": "admin", "cyPwd": "admin", "cyToken": "local",
                        "isPushPic": 1, "isPushVideo": 0})

    def start_console(self):
        def reader():
            for line in sys.stdin:
                self.console.put(line)
        threading.Thread(target=reader, daemon=True).start()
        print(HELP)

    # --- application flow (mirrors the official app's capture) ---------
    def login(self):
        self.send_json({"pro": "check_user", "cmd": 100, "devmac": "0000"})

    def start_stream(self):
        # app capture (CEST, Sept.) sent tz=-3600 == time.timezone for CET
        self.send_json({"pro": "set_datetime", "cmd": 126,
                        "time": int(time.time()), "tz": time.timezone})
        self.send_json({"pro": "dev_control", "cmd": 102, "heart": 1})
        # 'stream' is NOT sent here: this camera starts streaming on connect,
        # and a 'stream' request while video flows stalled its command
        # handling. The watchdog in run() requests video only if none
        # arrives (or FORCE_STREAM_CMD is set).
        if FORCE_STREAM_CMD:
            self.request_video()
        # get_parms is NOT sent automatically: on this camera it blocks the
        # command handling (probably an upgrade-server lookup for
        # server_ver/upgrade without internet) -- every later command
        # (ir, led, ...) then sat in the camera's queue unanswered.
        self.streaming = True
        self.stream_started = time.monotonic()
        for line in self.startup_cmds:
            self.do_command(line)

    def request_video(self):
        self.video_requested_at = time.monotonic()
        self.outq.insert(0, [{"pro": "stream", "cmd": CMD_STREAM, "video": 1,
                              "camsmode": 0, "user": USERNAME, "pwd": PASSWORD}])
        self.pump()

    def run(self):
        if not self.connect():
            print("Camera not found. Are you connected to the camera's WiFi?")
            return
        self.login()
        self.start_console()
        login_sent = last_alive = last_heart = time.monotonic()
        try:
            while not self.player.exited():
                dec, addr = self.recv(0.05)
                while dec is not None:
                    if addr == self.addr:
                        self.handle(dec)
                    self.sock.setblocking(False)
                    try:
                        data, addr = self.sock.recvfrom(65536)
                        dec = cs2_decrypt(data)
                    except (BlockingIOError, ConnectionResetError, OSError):
                        dec = None
                self.flush_acks()

                while not self.console.empty():
                    self.do_command(self.console.get())

                now = time.monotonic()
                if self.cmd_buf and now - self.cmd_buf_since > 1.0:
                    self.flush_partial()
                self.resend_unacked(now)
                self.check_replies(now)
                if now - last_alive > KEEPALIVE_INTERVAL:
                    self.send(pkt(T_ALIVE))
                    last_alive = now
                if not self.logged_in and now - login_sent > 3.0:
                    # no check_user reply -- still try to request the stream
                    log("no check_user reply, requesting stream anyway")
                    self.logged_in = True
                    self.start_stream()
                if (HEART_INTERVAL and self.streaming and now - last_heart > HEART_INTERVAL
                        and not self.outq and not self.busy(now)):
                    self.send_json({"pro": "dev_control", "cmd": 102, "heart": 1})
                    last_heart = now
                no_video = (now - self.stream_started > 2 if self.last_video is None
                            else now - self.last_video > 5)
                if self.streaming and no_video and now - self.video_requested_at > 15:
                    log("no video -- requesting stream")
                    self.request_video()
                self.pump()
        except KeyboardInterrupt:
            pass
        except ConnectionAbortedError as e:
            print(e)
        finally:
            try:
                self.send(pkt(T_CLOSE))
            except OSError:
                pass
            self.sock.close()
            self.player.close()
            print(f"Stopped after {self.frames} frames.")


def start_push_listener(port):
    """Logs whatever the camera sends to the push target (TCP and UDP),
    and saves embedded JPEG snapshots."""
    def handle(data, src, proto):
        print(f"[{time.strftime('%H:%M:%S')}] *** PUSH ({proto} from {src}) "
              f"{len(data)} bytes: {data[:200]!r}", flush=True)
        start = data.find(b"\xff\xd8")
        if start >= 0:
            path = os.path.join(OUT_DIR, time.strftime("motion_%Y%m%d_%H%M%S.jpg"))
            with open(path, "wb") as f:
                f.write(data[start:])
            print("    snapshot saved:", path, flush=True)

    def udp():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        while True:
            data, src = s.recvfrom(65536)
            handle(data, src, "udp")

    def tcp_client(conn, src):
        conn.settimeout(5)
        buf = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        conn.close()
        if buf:
            handle(buf, src, "tcp")

    def tcp():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        while True:
            conn, src = s.accept()
            print(f"[{time.strftime('%H:%M:%S')}] *** PUSH: camera opened TCP connection "
                  f"from {src}", flush=True)
            threading.Thread(target=tcp_client, args=(conn, src), daemon=True).start()

    for fn in (udp, tcp):
        threading.Thread(target=fn, daemon=True).start()
    log(f"push listener on tcp/udp port {port} -- on Windows allow Python through "
        f"the firewall (private network), otherwise nothing can arrive")


# ---------------------------------------------------------------------------
# Decode a capture of the official app (PCAPdroid / Wireshark .pcap/.pcapng)
# ---------------------------------------------------------------------------

def _pcap_packets(path):
    """Yields (timestamp, ip_payload_bytes) from pcap or pcapng files."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":                  # pcapng
        pos, linktypes, endian = 0, [], "<"
        while pos + 12 <= len(data):
            btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
            if btype == 0x0A0D0D0A:
                endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                btype, blen = struct.unpack(endian + "II", data[pos:pos + 8])
                linktypes = []
            elif btype == 1:                              # interface description
                linktypes.append(struct.unpack(endian + "H", data[pos + 8:pos + 10])[0])
            elif btype == 6:                              # enhanced packet
                iface, ts_hi, ts_lo, caplen = struct.unpack(endian + "IIII", data[pos + 8:pos + 24])
                frame = data[pos + 28:pos + 28 + caplen]
                lt = linktypes[iface] if iface < len(linktypes) else 1
                yield ((ts_hi << 32) | ts_lo) / 1e6, _strip_link(lt, frame)
            if blen < 12:
                break
            pos += blen
        return
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a pcap/pcapng file")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    while pos + 16 <= len(data):
        sec, frac, caplen, _ = struct.unpack(endian + "IIII", data[pos:pos + 16])
        frame = data[pos + 16:pos + 16 + caplen]
        pos += 16 + caplen
        yield sec + frac / (1e9 if nano else 1e6), _strip_link(linktype, frame)


def _strip_link(linktype, frame):
    if linktype == 1:                  # Ethernet
        return frame[14:] if frame[12:14] == b"\x08\x00" else None
    if linktype == 113:                # Linux cooked
        return frame[16:]
    if linktype == 276:                # Linux cooked v2
        return frame[20:]
    return frame                       # raw IP (101/228), PCAPdroid default


def decode_capture(path, show_video=False):
    """Prints every PPPP packet in an app capture, decrypted, with the JSON
    commands in readable form. Use it to learn the exact commands the app
    sends, e.g. while switching motion detection on/off in the app."""
    names = {v: k for k, v in globals().items() if k.startswith("T_") and isinstance(v, int)}
    t0 = None
    for ts, ip in _pcap_packets(path):
        if not ip or ip[0] >> 4 != 4 or ip[9] != 17:
            continue
        ihl = (ip[0] & 0x0f) * 4
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
        payload = ip[ihl + 8:]
        if not payload:
            continue
        dec = cs2_decrypt(payload)
        if dec[0] != MAGIC:
            continue
        t0 = t0 or ts
        ptype = dec[1]
        head = f"{ts - t0:8.3f} {src}:{sport} -> {dst}:{dport} {names.get(ptype, hex(ptype))[2:]}"
        if ptype == T_DRW and len(dec) >= 8:
            ch, idx = dec[5], struct.unpack(">H", dec[6:8])[0]
            if ch == CH_CMD:
                recs = parse_json_records(dec[8:])
                print(f"{head} ch0 idx={idx}")
                for r in recs or [{"_raw": dec[8:72].hex()}]:
                    print("          ", json.dumps(r, ensure_ascii=False))
            elif show_video:
                print(f"{head} ch{ch} idx={idx} {len(dec) - 8} bytes")
        elif ptype not in (T_DRW, T_DRW_ACK, T_ALIVE, T_ALIVE_ACK):
            print(f"{head} {dec[:24].hex()}")


# ---------------------------------------------------------------------------
# Offline self-test against packets captured from the official app
# ---------------------------------------------------------------------------

CAPTURED = {
    "punch": "9fd030f81fff64d2aa277276d034dc06995f8bcc7a36f428",
    "alive": "9f71d6f0",
    "check_user": "9f41de135412f85a5063679aa22315577f5187c1c18cbb8204e0f29ffa65cf246bd6d2"
                  "86e8a18340993c6cf60e910869708df56eb4c829b051c7b051d50182128befb186f09a"
                  "891b86a3e16af366077cc831b4c8257a00585644",
    "dev_control": "9f41de14c5732693e60d20c7c5732690f61cbbd2c551cd914e54648dfbb1caa5af6035"
                   "e164f0dba247bae1792be4333931fd09edbc0f53677ef441b04353247eeedd692fdc3e"
                   "b2a063e5bdfa52f0d99226b2ac0306",
}


def selftest():
    ok = True
    for name, hexdata in CAPTURED.items():
        raw = bytes.fromhex(hexdata)
        dec = cs2_decrypt(raw)
        good = cs2_encrypt(dec) == raw and dec[0] == MAGIC
        print(f"{name:12s} {'OK ' if good else 'BAD'} {dec[:24].hex()}  {dec[16:].decode('latin1')[:70]!r}")
        ok &= good
    ok &= cs2_decrypt(bytes.fromhex(CAPTURED["alive"])) == pkt(T_ALIVE)
    ok &= cs2_decrypt(bytes.fromhex(CAPTURED["punch"])) == make_punch()
    rec = parse_json_records(cs2_decrypt(bytes.fromhex(CAPTURED["check_user"]))[8:])
    ok &= rec and rec[0].get("pro") == "check_user"
    # camera replies use preamble 06 0a a1 80 (seen on EEE-304142)
    ok &= parse_json_records(bytes.fromhex("060aa180") + struct.pack("<I", 12)
                             + b'{"cmd":100}\n\t') == [{"cmd": 100}]
    # JSON record split over two Drw packets
    rec = json_record({"cmd": 107, "x": "y" * 50})
    part1, rest = parse_json_records(rec[:30], keep_partial=True)
    part2, rest = parse_json_records(rest + rec[30:], keep_partial=True)
    ok &= part1 == [] and part2 == [{"cmd": 107, "x": "y" * 50}] and rest == b""
    # wrap-around of the 16-bit Drw index
    fa = FrameAssembler()
    seq = [(0xfffe, VIDEO_MARKER + b"\0" * 28 + b"\x00\x00\x00\x01A"),
           (0xffff, b"B"), (0x0000, VIDEO_MARKER + b"\0" * 28 + b"C")]
    frames = [f for i, p in seq for f in fa.feed(i, p)]
    ok &= frames == [(VIDEO_MARKER + b"\0" * 28, b"\x00\x00\x00\x01AB")]
    print("SELFTEST", "PASSED" if ok else "FAILED")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--decode", metavar="PCAP",
                    help="decrypt an app capture (.pcap/.pcapng) and print its JSON commands")
    ap.add_argument("--ip", default=CAMERA_IP)
    ap.add_argument("--led", choices=["on", "off"], help="set status LED after login")
    ap.add_argument("--ir", choices=["on", "off"], help="set infrared mode after login")
    ap.add_argument("--push-listen", action="store_true",
                    help="EXPERIMENTAL: point the camera's alarm push (set_cypush) "
                         f"at this PC and log what arrives on port {PUSH_PORT}")
    args = ap.parse_args()
    CAMERA_IP = args.ip
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    if args.decode:
        decode_capture(args.decode)
        sys.exit(0)
    session = Session()
    if args.led:
        session.startup_cmds.append("led " + args.led)
    if args.ir:
        session.startup_cmds.append("ir " + args.ir)
    if args.push_listen:
        start_push_listener(PUSH_PORT)
        session.startup_cmds.append("pushhere")
    session.run()
