import socket
import threading

from aes import ManualAES
from common import *

# Master key tiap entitas (sekarang bebas panjangnya karena selalu di-hash dengan SHA-256)
master_keys_text = {
    "ALICE": "default_A",
    "BOB": "default_B",
}

keys = {
    "ALICE": ManualAES(master_keys_text["ALICE"]),
    "BOB": ManualAES(master_keys_text["BOB"]),
}
keys_lock = threading.Lock()


def handle_client(conn, addr):
    """Melayani satu request: langkah 1 (terima) dan langkah 2 (balas)."""
    try:
        msg_type, payload = recv_msg(conn)
        if msg_type != T_KDC_REQ:
            send_msg(conn, T_ERR, b"Tipe pesan tidak dikenal")
            return

        id_a, id_b, n1 = parse_kdc_req(payload)
        print(f"\n[KDC] Request dari {addr[0]}: {id_a} -> {id_b}, N1={n1.decode()}")

        with keys_lock:
            ka = keys.get(id_a)
            kb = keys.get(id_b)
        if ka is None or kb is None:
            print(f"[KDC] Ditolak: ID tidak dikenal ({id_a}, {id_b})")
            send_msg(conn, T_ERR, b"ID tidak dikenal")
            return

        # Session key baru per request, ticket untuk Bob, balasan untuk Alice
        ks = new_session_key()
        ticket = build_ticket(kb, ks, id_a)
        resp = build_kdc_resp(ka, ks, id_a, id_b, n1, ticket)
        send_msg(conn, T_KDC_RESP, resp)

        print(f"[KDC] Ks (plain, hanya di KDC) : {ks.hex()}")
        print(f"[KDC] Ticket E(Kb)             : {ticket.hex()}")
        print(f"[KDC] Balasan E(Ka)            : {resp.hex()}")
    except Exception as e:
        print(f"[KDC] Error: {e}")
    finally:
        conn.close()


def kdc_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[KDC] Listening di {host}:{port}")
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


def change_key(entity):
    new = input(f"Master key BARU untuk {entity}: ").strip()
    try:
        check_master_key(new)
        with keys_lock:
            master_keys_text[entity] = new
            keys[entity] = ManualAES(new)
        print(f"[KDC] Master key {entity} diperbarui.")
    except ValueError as e:
        print(f"[KDC] Ditolak: {e}")


if __name__ == "__main__":
    host = input("Bind IP KDC (kosong = 0.0.0.0): ").strip() or "0.0.0.0"
    threading.Thread(target=kdc_server, args=(host, KDC_PORT), daemon=True).start()

    while True:
        print("\n=== MENU KDC ===")
        print(f"1. Ubah master key ALICE ('{master_keys_text['ALICE']}')")
        print(f"2. Ubah master key BOB ('{master_keys_text['BOB']}')")
        print("3. Lihat entitas terdaftar")
        print("0. Keluar")
        pilihan = input("Pilih: ").strip()
        if pilihan == "1":
            change_key("ALICE")
        elif pilihan == "2":
            change_key("BOB")
        elif pilihan == "3":
            with keys_lock:
                print("Terdaftar:", ", ".join(keys))
        elif pilihan == "0":
            break
        else:
            print("Pilihan tidak valid.")
