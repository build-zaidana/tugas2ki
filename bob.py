import socket
import threading
import sys

from aes import ManualAES
from common import *

# Master key awal Bob (default sesuai KDC)
master_key = "default_B"
kb_cipher = ManualAES(master_key)
key_lock = threading.Lock()


def receive_loop(sock, ks_aes):
    """Thread penerima pesan dua arah setelah handshake selesai."""
    while True:
        try:
            msg_type, payload = recv_msg(sock)
            if msg_type == T_MSG:
                plaintext = ks_aes.decrypt(payload).decode('utf-8', errors='replace')
                if plaintext.lower() in ["/quit", "exit"]:
                    print("\n[Sistem] Alice telah mengakhiri obrolan. Tekan Enter untuk kembali ke menu.")
                    break
                print(f"\n[Bob] Ciphertext diterima (hex): {hexs(payload)}")
                print(f"[Alice -> Bob]: {plaintext}")
                print("[Bob] Pesan: ", end="", flush=True)
            elif msg_type == T_ERR:
                print(f"\n[Bob] Error dari lawan: {payload.decode('ascii', errors='replace')}")
                break
        except (ConnectionError, OSError, Exception):
            # Koneksi ditutup dari salah satu sisi secara aman
            break


def handle_alice(conn, addr):
    global kb_cipher
    print(f"\n[Bob] Menerima koneksi dari {addr[0]}:{addr[1]}")
    try:
        # Langkah 3: Terima TICKET dari Alice
        msg_type, payload = recv_msg(conn)
        if msg_type != T_TICKET:
            print("[Bob] Pesan bukan T_TICKET")
            send_msg(conn, T_ERR, b"Harus mengirim Ticket terlebih dahulu")
            return

        print(f"[Bob] Ticket (hex) diterima: {hexs(payload)}")

        with key_lock:
            current_kb = kb_cipher

        try:
            ks, id_a = parse_ticket(current_kb, payload)
        except Exception as e:
            print(f"[Bob] Gagal dekripsi ticket (Master key Bob salah?): {e}")
            send_msg(conn, T_ERR, b"Dekripsi Ticket Gagal")
            return

        print(f"[Bob] Ticket dekripsi sukses! Session Key (Ks): {hexs(ks)}, Dari ID: {id_a}")

        ks_aes = ManualAES(ks)

        # Langkah 4: Bob -> Alice (Kirim E(Ks, N2))
        n2 = new_nonce()  # Berupa bytes, misal: b'48210937'
        enc_n2 = ks_aes.encrypt(n2)
        print(f"[Bob] Mengirim N2 (Nonce B) = {n2.decode()}: {hexs(enc_n2)}")
        send_msg(conn, T_NONCE_B, enc_n2)

        # Langkah 5: Terima E(Ks, f(N2)) dari Alice
        msg_type, payload = recv_msg(conn)
        if msg_type != T_NONCE_ACK:
            print("[Bob] Pesan bukan T_NONCE_ACK")
            return

        dec_ack = ks_aes.decrypt(payload)  # Berupa bytes
        expected_ack = f_nonce(n2)         # Berupa bytes
        print(f"[Bob] Terima ACK f(N2): {dec_ack.decode(errors='replace')} (Ekspektasi: {expected_ack.decode()})")

        if dec_ack != expected_ack:
            print("[Bob] Autentikasi Gagal! Nonce ACK tidak sesuai.")
            send_msg(conn, T_ERR, b"Verifikasi Nonce Gagal")
            return

        print("[Bob] *** Handshake & Verifikasi Berhasil! Chat terenkripsi dimulai. ***")
        print("Catatan: Ketik '/quit' atau 'exit' untuk mengakhiri chat dan kembali ke menu.\n")

        # Jalankan thread penerima pesan dari Alice
        threading.Thread(target=receive_loop, args=(conn, ks_aes), daemon=True).start()

        # Loop pengiriman pesan ke Alice
        while True:
            try:
                msg = input("[Bob] Pesan: ").strip()
                if not msg:
                    continue

                # Cek jika pengguna mengetik perintah keluar
                if msg.lower() in ["/quit", "exit"]:
                    print("[Bob] Mengakhiri obrolan...")
                    enc_quit = ks_aes.encrypt(msg.encode('utf-8'))
                    send_msg(conn, T_MSG, enc_quit)
                    break

                enc_msg = ks_aes.encrypt(msg.encode('utf-8'))
                print(f"[Bob] Ciphertext (hex) dikirim: {hexs(enc_msg)}")
                send_msg(conn, T_MSG, enc_msg)
            except (ConnectionError, OSError):
                break

    except Exception as e:
        print(f"[Bob] Error saat melayani Alice: {e}")
    finally:
        conn.close()


def change_master_key():
    global master_key, kb_cipher
    new_key = input("Masukkan Master Key BARU untuk BOB: ").strip()
    try:
        check_master_key(new_key)
        with key_lock:
            master_key = new_key
            kb_cipher = ManualAES(master_key)
        print(f"[Bob] Master Key berhasil diperbarui menjadi: '{master_key}'")
    except ValueError as e:
        print(f"[Bob] Gagal meng-update key: {e}")


def main():
    host = input("Bind IP Server Bob (kosong = 0.0.0.0): ").strip() or "0.0.0.0"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, BOB_PORT))
    server.listen(1)
    print(f"[Bob] Listening di {host}:{BOB_PORT} (Master Key default: '{master_key}')")

    while True:
        print("\n=== MENU BOB ===")
        print(f"Master Key saat ini: '{master_key}'")
        print("1. Mulai tunggu koneksi Alice")
        print("2. Ubah Master Key")
        print("0. Keluar")
        pilihan = input("Pilih: ").strip()

        if pilihan == "1":
            conn, addr = server.accept()
            handle_alice(conn, addr)
        elif pilihan == "2":
            change_master_key()
        elif pilihan == "0":
            break
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
