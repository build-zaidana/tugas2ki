import socket
import threading
import sys

from aes import ManualAES
from common import *

# Master key awal Alice (default)
master_key = "default_A"
ka_cipher = ManualAES(master_key)


def receive_loop(sock, ks_aes):
    """Thread penerima pesan dua arah setelah handshake selesai."""
    while True:
        try:
            msg_type, payload = recv_msg(sock)
            if msg_type == T_MSG:
                plaintext = ks_aes.decrypt(payload).decode('utf-8', errors='replace')
                if plaintext.lower() in ["/quit", "exit"]:
                    print("\n[Sistem] Bob telah mengakhiri obrolan. Tekan Enter untuk kembali ke menu.")
                    break
                print(f"\n[Alice] Ciphertext diterima (hex): {hexs(payload)}")
                print(f"[Bob -> Alice]: {plaintext}")
                print("[Alice] Pesan: ", end="", flush=True)
            elif msg_type == T_ERR:
                print(f"\n[Alice] Error dari Bob: {payload.decode('ascii', errors='replace')}")
                break
        except (ConnectionError, OSError, Exception):
            # Koneksi ditutup dari salah satu sisi secara aman
            break


def start_handshake_and_chat(kdc_ip, bob_ip):
    global ka_cipher

    # ==================== LANGKAH 1 & 2: ALICE <-> KDC ====================
    print("\n--- [Langkah 1 & 2] Minta Session Key & Ticket ke KDC ---")
    try:
        sock_kdc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock_kdc.connect((kdc_ip, KDC_PORT))

        n1 = new_nonce()
        req_payload = build_kdc_req(ID_ALICE, ID_BOB, n1)
        print(f"[Alice] Kirim T_KDC_REQ: ID_A={ID_ALICE}, ID_B={ID_BOB}, N1={n1.decode()}")
        send_msg(sock_kdc, T_KDC_REQ, req_payload)

        msg_type, payload = recv_msg(sock_kdc)
        sock_kdc.close()

        if msg_type == T_ERR:
            print(f"[Alice] KDC Menolak Request: {payload.decode('ascii', errors='replace')}")
            return
        elif msg_type != T_KDC_RESP:
            print(f"[Alice] Tipe pesan KDC tidak valid ({msg_type})")
            return

        print(f"[Alice] Respon KDC (hex) diterima: {hexs(payload)}")
        try:
            ks, id_a_resp, id_b_resp, n1_resp, ticket = parse_kdc_resp(ka_cipher, payload)
        except Exception as e:
            print(f"[Alice] Gagal dekripsi respon KDC (Master key Alice salah?): {e}")
            return

        # Verifikasi Balasan KDC
        if n1_resp != n1 or id_b_resp != ID_BOB:
            print("[Alice] Error: Verifikasi N1 atau ID_B dari KDC Gagal!")
            return

        print(f"[Alice] Dekripsi KDC_RESP Sukses!")
        print(f"  -> Session Key (Ks): {hexs(ks)}")
        print(f"  -> Ticket E(Kb)    : {hexs(ticket)}")

    except Exception as e:
        print(f"[Alice] Gagal berkomunikasi dengan KDC: {e}")
        return

    # ==================== LANGKAH 3, 4, 5: ALICE <-> BOB ====================
    print("\n--- [Langkah 3, 4, 5] Autentikasi dengan Bob ---")
    sock_bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock_bob.connect((bob_ip, BOB_PORT))

        # Langkah 3: Kirim Ticket ke Bob
        print(f"[Alice] Kirim Ticket ke Bob...")
        send_msg(sock_bob, T_TICKET, ticket)

        # Langkah 4: Terima Nonce N2 dari Bob E(Ks, N2)
        msg_type, payload = recv_msg(sock_bob)
        if msg_type != T_NONCE_B:
            print("[Alice] Balasan dari Bob bukan T_NONCE_B")
            sock_bob.close()
            return

        ks_aes = ManualAES(ks)
        n2 = ks_aes.decrypt(payload)
        print(f"[Alice] Nonce N2 dari Bob (E(Ks, N2)): {n2.decode(errors='replace')}")

        # Langkah 5: Kirim Balasan ACK E(Ks, f(N2))
        f_n2 = f_nonce(n2)
        enc_f_n2 = ks_aes.encrypt(f_n2)
        print(f"[Alice] Kirim ACK f(N2) = {f_n2.decode()}: {hexs(enc_f_n2)}")
        send_msg(sock_bob, T_NONCE_ACK, enc_f_n2)

        print("[Alice] *** Handshake & Verifikasi Berhasil! Chat terenkripsi dimulai. ***")
        print("Catatan: Ketik '/quit' atau 'exit' untuk mengakhiri chat dan kembali ke menu.\n")

        # Jalankan thread penerima pesan dari Bob
        threading.Thread(target=receive_loop, args=(sock_bob, ks_aes), daemon=True).start()

        # Loop pengiriman pesan ke Bob
        while True:
            try:
                msg = input("[Alice] Pesan: ").strip()
                if not msg:
                    continue

                # Cek jika pengguna mengetik perintah keluar
                if msg.lower() in ["/quit", "exit"]:
                    print("[Alice] Mengakhiri obrolan...")
                    enc_quit = ks_aes.encrypt(msg.encode('utf-8'))
                    send_msg(sock_bob, T_MSG, enc_quit)
                    break

                enc_msg = ks_aes.encrypt(msg.encode('utf-8'))
                print(f"[Alice] Ciphertext (hex) dikirim: {hexs(enc_msg)}")
                send_msg(sock_bob, T_MSG, enc_msg)
            except (ConnectionError, OSError):
                break

    except Exception as e:
        print(f"[Alice] Error saat terhubung ke Bob: {e}")
    finally:
        sock_bob.close()


def change_master_key():
    global master_key, ka_cipher
    new_key = input("Masukkan Master Key BARU untuk ALICE: ").strip()
    try:
        check_master_key(new_key)
        master_key = new_key
        ka_cipher = ManualAES(master_key)
        print(f"[Alice] Master Key berhasil diperbarui menjadi: '{master_key}'")
    except ValueError as e:
        print(f"[Alice] Gagal meng-update key: {e}")


def main():
    kdc_ip = input("Masukkan IP KDC (default: 127.0.0.1): ").strip() or "127.0.0.1"
    bob_ip = input("Masukkan IP Bob (default: 127.0.0.1): ").strip() or "127.0.0.1"

    while True:
        print("\n=== MENU ALICE ===")
        print(f"Master Key saat ini: '{master_key}'")
        print("1. Mulai Handshake & Chat dengan Bob")
        print("2. Ubah Master Key")
        print("0. Keluar")
        pilihan = input("Pilih: ").strip()

        if pilihan == "1":
            start_handshake_and_chat(kdc_ip, bob_ip)
        elif pilihan == "2":
            change_master_key()
        elif pilihan == "0":
            break
        else:
            print("Pilihan tidak valid.")


if __name__ == "__main__":
    main()
