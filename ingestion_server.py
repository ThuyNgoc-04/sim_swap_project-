import socket
import logging
from processor import SimSwapProcessor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

SERVER_IP = "0.0.0.0"
SERVER_PORT = 1813

def parse_radius_packet(payload: str):
    """
    Bóc tách chuỗi plaintext dạng: MSISDN=0396888111|IP=10.60.20.14|STATUS=START
    Trả về tuple: (msisdn, ip_address, status)
    """
    try:
        parts = payload.split('|')
        data = {}
        for part in parts:
            if '=' in part:
                key, val = part.split('=', 1)
                data[key.strip()] = val.strip()
        return data.get('MSISDN'), data.get('IP'), data.get('STATUS')
    except Exception as e:
        logging.error(f"[PARSE ERROR] Lỗi bóc tách gói tin: {e}")
        return None, None, None

def run_ingestion_module():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Khởi tạo processor xử lý nghiệp vụ và quản lý Redis
    processor = SimSwapProcessor()

    try:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        logging.info(f"[INGESTION MODULE] Đã khởi động. Đang lắng nghe bản tin RADIUS Accounting tại cổng UDP {SERVER_PORT}...")
        
        while True:
            # Nhận gói tin UDP thô từ Client
            data_bytes, client_address = server_socket.recvfrom(1024)
            plaintext_message = data_bytes.decode('utf-8')
            
            # 1. Log xác nhận đã nhận bản tin
            logging.info(f"[NHẬN THÀNH CÔNG] Nguồn: {client_address} | Payload: {plaintext_message}")
            
            # 2. Bóc tách thông tin và chuyển giao toàn bộ cho Processor xử lý nghiệp vụ & Redis
            msisdn, ip, status = parse_radius_packet(plaintext_message)
            
            if msisdn and ip and status and processor:
                processor.evaluate_session(msisdn, ip, status)
            else:
                logging.warning("[PARSER ERROR] Gói tin không hợp lệ hoặc thiếu dữ liệu!")

    except KeyboardInterrupt:
        logging.info("[INGESTION MODULE] Đã dừng hoạt động theo yêu cầu.")
    except Exception as e:
        logging.error(f"[LỖI HỆ THỐNG] {e}")
    finally:
        server_socket.close()
        logging.info("[INGESTION MODULE] Đã đóng socket an toàn.")

if __name__ == "__main__":
    run_ingestion_module()
