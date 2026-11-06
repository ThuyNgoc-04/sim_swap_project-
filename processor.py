from datetime import datetime
import redis
import logging
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

class SimSwapProcessor:
    def __init__(self, host='localhost', port=6379, db=0):
        try:
            self.redis_client = redis.Redis(
                host=host, port=port, db=db, decode_responses=True
            )
            self.redis_client.ping()
            logging.info("[PROCESSOR] Đã kết nối thành công tới Redis để xử lý nghiệp vụ.")
        except Exception as e:
            logging.error(f"[PROCESSOR ERROR] Không thể kết nối Redis: {e}")
            self.redis_client = None

    def evaluate_session(self, msisdn: str, incoming_ip: str, status: str):
        """
        Thuật toán kiểm tra sự thay đổi IP đột ngột (Dấu hiệu SIM Swap / Device Swap)
        """
        if not self.redis_client:
            logging.error("[PROCESSOR ERROR] Redis client chưa sẵn sàng.")
            return

        session_key = f"session:{msisdn}"
        history_key = f"history_ip:{msisdn}"

        if status == "START":
            current_ip = self.redis_client.get(session_key)
            if current_ip and current_ip != incoming_ip:
                logging.warning(
                    f"⚠️ [SIM SWAP ALERT] Phát hiện thay đổi IP bất thường cho MSISDN [{msisdn}]! "
                    f"IP cũ: [{current_ip}] -> IP mới: [{incoming_ip}]"
                )
                alert_payload = {
                    "event_type": "SIM_SWAP_DETECTED",
                    "msisdn": msisdn,
                    "old_ip": current_ip,
                    "new_ip": incoming_ip,
                    "risk_level": "HIGH",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                self.redis_client.publish("sim_swap_alerts", json.dumps(alert_payload))
                self.redis_client.rpush(history_key, f"OLD:{current_ip}->NEW:{incoming_ip}")
            else:
                logging.info(f"[PROCESSOR] Phiên START hợp lệ cho MSISDN [{msisdn}] với IP [{incoming_ip}]")
            
            self.redis_client.set(session_key, incoming_ip)

        elif status == "STOP":
            if self.redis_client.exists(session_key):
                self.redis_client.delete(session_key)
                logging.info(f"[PROCESSOR] Đã đóng phiên (STOP) cho MSISDN [{msisdn}]")

if __name__ == "__main__":
    processor = SimSwapProcessor()
    processor.evaluate_session("0396888111", "10.60.20.14", "START")    
    processor.evaluate_session("0396888111", "192.168.1.100", "START")
