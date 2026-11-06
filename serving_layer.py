from fastapi import FastAPI, Header, HTTPException, Depends
import redis
import logging
from datetime import datetime

app = FastAPI(
    title="CAMARA SIM Swap Detection API Gateway",
    version="1.0.0",
    description="API cung cấp dịch vụ kiểm tra rủi ro đổi SIM / Device Swap thời gian thực dựa trên luồng RADIUS."
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

try:
    redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
    redis_client.ping()
    logging.info("[API GATEWAY] Đã kết nối thành công tới Redis Storage Layer.")
except Exception as e:
    logging.error(f"[API GATEWAY ERROR] Không thể kết nối Redis: {e}")
    redis_client = None

VALID_API_KEYS = {"camara-client-key-2026", "sec-network-enterprise-key"}

def verify_api_key(x_api_key: str = Header(None)):
    """
    1. API Key Header Authentication: Kiểm tra tính hợp lệ của khóa xác thực từ header 'X-API-Key'
    """
    if not x_api_key or x_api_key not in VALID_API_KEYS:
        logging.warning(f"[SECURITY ALERT] Truy cập bị từ chối do API Key không hợp lệ hoặc bị thiếu: {x_api_key}")
        raise HTTPException(
            status_code=401, 
            detail="Unauthorized: Invalid or missing API Key in 'X-API-Key' header."
        )
    return x_api_key

def check_rate_limit(client_id: str = "default_client"):
    """
    3. Rate Limiting: Giới hạn tần suất gọi API (Tối đa 15 requests / 10 giây)
    """
    if not redis_client:
        return
    
    rate_key = f"rate_limit:{client_id}"
    current_requests = redis_client.get(rate_key)
    
    if current_requests and int(current_requests) >= 15:
        logging.warning(f"[RATE LIMIT] Client [{client_id}] vượt quá hạn mức gọi API cho phép.")
        raise HTTPException(
            status_code=429, 
            detail="Too Many Requests: Rate limit exceeded. Please try again later."
        )
    
    pipe = redis_client.pipeline()
    pipe.incr(rate_key, 1)
    if not current_requests:
        pipe.expire(rate_key, 10)  
    pipe.execute()

@app.post("/nis/v1/sim-swap/check", summary="Kiểm tra trạng thái SIM Swap theo chuẩn CAMARA")
def check_sim_swap(
    msisdn: str,
    api_key: str = Depends(verify_api_key)
):
    """
    Endpoint chính thực hiện:
    - Kiểm tra Rate Limit.
    - Truy vấn dữ liệu từ Storage Layer (Redis).
    - Đánh giá mức độ rủi ro (Risk Assessment).
    - Ghi nhận Audit Transaction Log.
    """
    check_rate_limit()

    if not redis_client:
        raise HTTPException(status_code=500, detail="Storage Layer (Redis) is currently unavailable.")

    session_key = f"session:{msisdn}"
    history_key = f"history_ip:{msisdn}"

    current_ip = redis_client.get(session_key)
    ip_history = redis_client.lrange(history_key, 0, -1)

    is_swapped = len(ip_history) > 0
    risk_level = "HIGH" if is_swapped else "LOW"

    audit_msg = f"[AUDIT LOG] API Call Success | MSISDN: {msisdn} | Risk Level: {risk_level} | History Count: {len(ip_history)}"
    logging.info(audit_msg)

    return {
        "net_nis": {
            "msisdn": msisdn,
            "latest_active_ip": current_ip if current_ip else "No active session",
            "sim_swap": is_swapped,
            "risk_level": risk_level,
            "swap_history": ip_history,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_gateway:app", host="127.0.0.1", port=8000, reload=True)
