import socket
import time

SERVER_IP = "127.0.0.1"
SERVER_PORT = 1813

def create_radius_accouting_packet(msisdn: str, ip_address: str, status: str) -> bytes:
    """
    Giả lập tạo gói tin RADIUS Accounting thô (Raw Byte Stream).
    Đóng gói thông tin MSISDN, IP và Trạng thái kết nối thành chuỗi byte.
    """
    packet_content = f"MSISDN={msisdn}|IP={ip_address}|STATUS={status}"
    return packet_content.encode('utf-8')

def run_radius_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[RADIUS CLIENT] Đã khởi động. Chuẩn bị bắn bản tin tới {SERVER_IP}:{SERVER_PORT}...")
    sim_sessions = [
        {"msisdn": "0396888111", "ip": "10.60.20.14"},
        {"msisdn": "0396888222", "ip": "10.60.20.15"},
        {"msisdn": "0396888333", "ip": "10.60.20.16"},
    ]

    try:
        is_first_round = True
        while True:
            for session in sim_sessions:
                msisdn = session["msisdn"]
                ip = session["ip"]

                if msisdn == "0396888111" and not is_first_round:
                    ip = "192.168.1.100"

                start_packet = create_radius_accouting_packet(msisdn, ip, "START")
                client_socket.sendto(start_packet, (SERVER_IP, SERVER_PORT))
                print(f"[SENT START] Thuê bao {msisdn} kết nối với IP {ip}")
                time.sleep(2)

                if not (msisdn == "0396888111" and not is_first_round):
                    stop_packet = create_radius_accouting_packet(msisdn, ip, "STOP")
                    client_socket.sendto(stop_packet, (SERVER_IP, SERVER_PORT))
                    print(f"[SENT STOP]  Thuê bao {msisdn} ngắt kết nối IP {ip}")
                    time.sleep(3)
                else:
                    print(f"[INFO] Giữ nguyên phiên active cho {msisdn} với IP mới để kích hoạt Alert!")
                    time.sleep(5)

            is_first_round = False

    except KeyboardInterrupt:
        print("\n[RADIUS CLIENT] Đã dừng chương trình giả lập.")   
    finally:
        client_socket.close()

if __name__ == "__main__":
    run_radius_client()
