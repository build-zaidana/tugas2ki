"""Modul bersama KDC, Alice, dan Bob. Format lengkap: lihat PROTOCOL.md."""
import os
import random
from aes import ManualAES

# --- Konfigurasi default ---
KDC_PORT = 5001
BOB_PORT = 6000
ID_ALICE = "ALICE"
ID_BOB = "BOB"

# --- Ukuran field (byte) ---
ID_LEN = 8
NONCE_LEN = 8
KEY_LEN = 16
TICKET_PLAIN_LEN = KEY_LEN + ID_LEN                                   # 24
TICKET_LEN = 32                                                       # E(Kb, Ks||ID_A)
KDC_RESP_PLAIN_LEN = KEY_LEN + ID_LEN + ID_LEN + NONCE_LEN + TICKET_LEN  # 72
KDC_RESP_LEN = 80                                                     # E(Ka, ...)

# --- Tipe pesan ---
T_KDC_REQ = 0x01
T_KDC_RESP = 0x02
T_TICKET = 0x03
T_NONCE_B = 0x04
T_NONCE_ACK = 0x05
T_MSG = 0x06
T_ERR = 0x7F

MAX_PAYLOAD = 1 << 20


# --- Framing socket: [TYPE 1B][LEN 4B big-endian][PAYLOAD] ---
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Koneksi ditutup sebelum data lengkap diterima")
        buf += chunk
    return buf


def send_msg(sock, msg_type, payload=b""):
    sock.sendall(bytes([msg_type]) + len(payload).to_bytes(4, "big") + payload)


def recv_msg(sock):
    """Mengembalikan (msg_type, payload)."""
    header = recv_exact(sock, 5)
    length = int.from_bytes(header[1:], "big")
    if length > MAX_PAYLOAD:
        raise ValueError(f"Payload terlalu besar: {length}")
    return header[0], recv_exact(sock, length)


# --- Field ASCII ---
def pack_id(name):
    raw = name.encode("ascii")
    if not raw or len(raw) > ID_LEN:
        raise ValueError(f"ID harus 1-{ID_LEN} karakter ASCII")
    return raw.ljust(ID_LEN, b" ")


def unpack_id(raw):
    return raw.decode("ascii").rstrip(" ")


def new_nonce():
    """Nonce 8 digit ASCII, contoh b'48210937'."""
    return f"{random.SystemRandom().randrange(10 ** NONCE_LEN):0{NONCE_LEN}d}".encode("ascii")


def f_nonce(nonce):
    """f(N) = N + 1, tetap 8 digit."""
    return f"{(int(nonce) + 1) % 10 ** NONCE_LEN:0{NONCE_LEN}d}".encode("ascii")


def new_session_key():
    return os.urandom(KEY_LEN)


def check_master_key(key):
    """Master key: string ASCII tidak boleh kosong."""
    if not key or not key.isascii():
        raise ValueError("Master key harus berupa karakter ASCII yang valid")
    return key


# --- Langkah 1: Alice -> KDC ---
def build_kdc_req(id_a, id_b, n1):
    return pack_id(id_a) + pack_id(id_b) + n1


def parse_kdc_req(payload):
    if len(payload) != 2 * ID_LEN + NONCE_LEN:
        raise ValueError("KDC_REQ panjangnya salah")
    return (unpack_id(payload[:8]), unpack_id(payload[8:16]), payload[16:24])


# --- Langkah 2: KDC -> Alice ---
def build_ticket(kb_cipher, ks, id_a):
    return kb_cipher.encrypt(ks + pack_id(id_a))


def parse_ticket(kb_cipher, ticket):
    """Mengembalikan (ks, id_a)."""
    plain = kb_cipher.decrypt(ticket)
    if len(plain) != TICKET_PLAIN_LEN:
        raise ValueError("Ticket tidak valid (master key Bob salah?)")
    return plain[:KEY_LEN], unpack_id(plain[KEY_LEN:])


def build_kdc_resp(ka_cipher, ks, id_a, id_b, n1, ticket):
    return ka_cipher.encrypt(ks + pack_id(id_a) + pack_id(id_b) + n1 + ticket)


def parse_kdc_resp(ka_cipher, payload):
    """Mengembalikan (ks, id_a, id_b, n1, ticket)."""
    plain = ka_cipher.decrypt(payload)
    if len(plain) != KDC_RESP_PLAIN_LEN:
        raise ValueError("KDC_RESP tidak valid (master key Alice salah?)")
    ks = plain[:16]
    id_a = unpack_id(plain[16:24])
    id_b = unpack_id(plain[24:32])
    n1 = plain[32:40]
    ticket = plain[40:72]
    return ks, id_a, id_b, n1, ticket


# --- Tampilan ---
def hexs(data):
    return data.hex()
