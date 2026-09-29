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
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

KEEPALIVE_INTERVAL = 1.0       # our own P2PAlive
RESEND_INTERVAL = 0.5          # resend un-acked outgoing Drw packets
HEART_INTERVAL = 10.0          # app sends dev_control/heart; repeated here
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

JSON_PREAMBLE = bytes.fromhex("060aa080")
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


def parse_json_records(payload):
    out, pos = [], 0
    while pos + 8 <= len(payload) and payload[pos:pos + 4] == JSON_PREAMBLE:
        n = struct.unpack("<I", payload[pos + 4:pos + 8])[0]
        raw = payload[pos + 8:pos + 8 + n]
        pos += 8 + n
        try:
            out.append(json.loads(raw.rstrip(b"\0").decode("utf-8", "replace")))
        except ValueError:
            out.append({"_raw": raw.hex()})
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
        for attempt in range(5):
            self.sock.sendto(cs2_encrypt(pkt(T_LAN_SEARCH)), (CAMERA_IP, DISCOVERY_PORT))
            self.sock.sendto(cs2_encrypt(pkt(T_LAN_SEARCH)), ("255.255.255.255", DISCOVERY_PORT))
            deadline = time.time() + 1.0
            while time.time() < deadline:
                dec, addr = self.recv(0.2)
                if not dec or dec[0] != MAGIC:
                    continue
                log(f"<- {addr} type=0x{dec[1]:02x} {dec[:24].hex()}")
                if dec[1] == T_PUNCH and self.addr is None:
                    self.addr = addr
                    log(f"camera session endpoint: {addr}")
                    self.send(make_punch())
                elif dec[1] == T_P2P_RDY and addr == self.addr:
                    log("P2P ready")
                    return True
            if self.addr:
                self.send(make_punch())
        return self.addr is not None

    # --- reliable command channel --------------------------------------
    def send_json(self, *objs):
        records = b""
        for o in objs:
            o = {**o, "user": USERNAME, "pwd": PASSWORD}
            records += json_record(o)
            log("-> JSON", o)
        idx = self.out_idx
        self.out_idx = (self.out_idx + 1) & 0xffff
        raw = make_drw(CH_CMD, idx, records)
        self.unacked[idx] = [raw, time.time()]
        self.send(raw)

    def resend_unacked(self, now):
        for idx, entry in self.unacked.items():
            if now - entry[1] > RESEND_INTERVAL:
                self.send(entry[0])
                entry[1] = now

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
            for obj in parse_json_records(payload):
                log("<- JSON", obj)
                if obj.get("cmd") == 100 and not self.logged_in:
                    self.logged_in = True
                    self.start_stream()
        elif ch == CH_VIDEO:
            if payload.startswith(VIDEO_MARKER) and self.frames < 3:
                log("frame header:", payload[:VIDEO_HEADER_LEN].hex(),
                    "data:", payload[VIDEO_HEADER_LEN:VIDEO_HEADER_LEN + 16].hex())
            for header, frame in self.assembler.feed(idx, payload):
                self.frames += 1
                if self.frames % 25 == 1:
                    log(f"frame #{self.frames}: {len(frame)} bytes")
                self.player.push(frame)

    # --- application flow (mirrors the official app's capture) ---------
    def login(self):
        self.send_json({"pro": "check_user", "cmd": 100, "devmac": "0000"})

    def start_stream(self):
        # app capture (CEST, Sept.) sent tz=-3600 == time.timezone for CET
        self.send_json({"pro": "set_datetime", "cmd": 126,
                        "time": int(time.time()), "tz": time.timezone})
        self.send_json({"pro": "dev_control", "cmd": 102, "heart": 1})
        self.send_json({"pro": "stream", "cmd": 111, "video": 1, "camsmode": 0},
                       {"pro": "get_parms", "cmd": 101})
        self.streaming = True

    def run(self):
        if not self.connect():
            print("Camera not found. Are you connected to the camera's WiFi?")
            return
        self.login()
        login_sent = last_alive = last_heart = time.time()
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

                now = time.time()
                self.resend_unacked(now)
                if now - last_alive > KEEPALIVE_INTERVAL:
                    self.send(pkt(T_ALIVE))
                    last_alive = now
                if not self.logged_in and now - login_sent > 3.0:
                    # no check_user reply -- still try to request the stream
                    log("no check_user reply, requesting stream anyway")
                    self.logged_in = True
                    self.start_stream()
                if self.streaming and now - last_heart > HEART_INTERVAL:
                    self.send_json({"pro": "dev_control", "cmd": 102, "heart": 1})
                    last_heart = now
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
    ap.add_argument("--ip", default=CAMERA_IP)
    args = ap.parse_args()
    CAMERA_IP = args.ip
    if args.selftest:
        sys.exit(0 if selftest() else 1)
    Session().run()
