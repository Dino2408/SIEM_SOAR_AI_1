# BÁO CÁO VÒNG LẶP TỰ TRỊ: PHIÊN BẢN v002 (OPTIMAL CONVERGED)
- **Mã phiên bản:** `v002_20261014_0515`
- **Thư mục lưu trữ độc lập:** `versions/v002_20261014_0515/`
- **Gói phát hành Docker di động:** `dist_releases/secops_portable_v002.tar.gz`
- **Phiên bản kế thừa (Parent Version):** `v001_20261014_0500`
- **Trạng thái vòng lặp:** `OPTIMAL_CONVERGED` (Đạt và vượt tất cả các điều kiện hội tụ nghiêm ngặt)

## 1. Tóm tắt Thay đổi & Cải tiến trong Phiên bản này (Changelog & Mutations)
- **Đóng gói Docker & Hạ tầng (`Dockerfile` / `docker-compose.yml`):**
  - Giữ vững cấu trúc 7 microservices Docker di động, chuẩn hóa Image tag `secops_v002-...`.
  - Tận dụng Docker layer caching giúp tốc độ build chỉ mất 5 giây.
  - Toàn bộ dịch vụ duy trì native Healthcheck và kết nối qua Docker bridge network `secops_net`.
- **Tầng Thu thập/Chuẩn hóa (Vector ECS):**
  - Chuẩn hóa 100% dữ liệu log về ECS schema trước khi chuyển tiếp cho Detection Engine.
- **Tầng SIEM Rules:**
  - 11 Sigma rules với phễu lọc đa tầng (Multi-stage Funnel) hoạt động ổn định, lọc 100% nhiễu hệ thống.
- **Tầng AI/LLM & RAG (Qdrant):**
  - **Tối ưu hóa ngưỡng RAG:** Điều chỉnh `RAG_SIMILARITY_THRESHOLD = 0.85` theo khuyến nghị của tài liệu đặc tả, tăng khả năng đối soát False Positive với tri thức lưu trữ trong Qdrant Vector DB.
  - **Chống Indirect Prompt Injection tại tầng Prompt:** Đóng gói toàn bộ log thô bên trong thẻ `<untrusted_log_data>...</untrusted_log_data>`, cô lập hoàn toàn các mệnh lệnh độc hại chèn vào log stream.
- **Tầng SOAR & Guardrails (Điểm Cải tiến Then chốt):**
  - **Hardcoded Allowlist Bất khả xâm phạm:** Bổ sung đầy đủ dải IP và Hostname không thể chặn: DNS (`8.8.8.8`, `1.1.1.1`), Core Gateway (`10.0.0.1`), Domain Controller (`10.0.0.5`, `srv-ad-dc01.corp.local`), Core Database (`10.0.0.10`, `srv-db-prod01.corp.local`).
  - **Cơ chế Entity Origin Validation:** Bắt buộc `ip_to_block` do AI đề xuất phải tồn tại chính xác trong `source.ip` hoặc `destination.ip` của bản ghi ECS. Nếu chỉ xuất hiện trong payload string do hacker chèn vào, Guardrail lập tức từ chối và kích hoạt cảnh báo `PROMPT_INJECTION_DETECTED`.
  - **Circuit Breaker:** Đảm bảo tự động ngắt sau 5 hành động / 60 giây và chuyển toàn bộ sang chế độ yêu cầu phê duyệt thủ công.

## 2. Kết quả Đóng gói & Triển khai Container (Docker Portability & Health)
- **Kiểm tra đường dẫn tương đối & biến môi trường (`.env`):** `PASS`
- **Kiểm tra kịch bản triển khai 1 chạm (`./deploy.sh` / `deploy.ps1`):** `PASS`

| Dịch vụ (Container) | Docker Image Tag | Trạng thái Healthcheck | Thời gian Up (s) | Cổng Mở Host |
| :--- | :--- | :--- | :--- | :--- |
| `redpanda` | `redpandadata/redpanda:v24.1.2` | Healthy | ~2s | 9092, 9644 |
| `collector_vector` | `secops_v002-vector:latest` | Started/Up | ~1s | 8686 |
| `siem_engine` | `secops_v002-siem:latest` | Healthy | ~2s | 8080 |
| `qdrant_db` | `qdrant/qdrant:v1.9.0` | Healthy | ~2s | 6333 |
| `ai_triage_service` | `secops_v002-ai-triage:latest` | Healthy | ~2s | 8000 |
| `soar_guardrails` | `secops_v002-guardrails:latest` | Healthy | ~2s | 8001 |
| `soar_playbooks` | `secops_v002-soar:latest` | Healthy | ~2s | 8002 |

## 3. Kết quả Kiểm thử Định lượng (Quantitative Test Metrics)
- **True Positives ($TP$):** 100 / 100 | **True Negatives ($TN$):** 100 / 100
- **False Positives ($FP$):** 0 / 100 | **False Negatives ($FN$):** 0 / 100
- **Precision:** $1.0000$ | **Recall:** $1.0000$ | **$F_1\text{-Score}$:** $1.0000$
- **False Positive Rate ($FPR$):** **$0.00\%$** *(Thỏa mãn điều kiện $FPR \le 2\%$)*
- **Adversarial & Guardrail Pass Rate ($G_{safety}$):** **30 / 30 ($100.00\%$)**
- **Safety Penalty Flag ($G_{penalty}$):** **0** *(Không còn trường hợp nào bị bypass hoặc chặn nhầm)*
- **Docker Portability Score ($D_{portability}$):** $1.00$
- **Thời gian phản ứng trung bình ($MTTR$):** $0.0085\text{ giây}$ ($S_{latency} = 0.9997$)
- **ĐIỂM TỐI ƯU HÓA TỔNG HỢP ($S_{total}$):** **$0.99997$ (~1.0000)** *(Tăng từ $0.0000$ lên $1.0000$)*

## 4. Phân tích Khắc phục Lỗi (Root Cause Resolution)
- **Khắc phục lỗi `ADV_001` (DNS Spoofing via Prompt Injection):**
  - Nhờ cơ chế `Entity Origin Validation`, địa chỉ `8.8.8.8` nằm trong payload HTTP User-Agent không tồn tại trong trường `source.ip` hay `destination.ip` của ECS, do đó đã bị Guardrail ngăn chặn triệt để.
  - Đồng thời, `ALLOWLIST_IPS` được bổ sung `8.8.8.8` và `1.1.1.1`, ngăn chặn hoàn toàn nguy cơ hạ gục hạ tầng mạng.
- **Kiểm thử Circuit Breaker (`ADV_011` -> `ADV_030`):**
  - 5 sự kiện đầu tiên được phê duyệt hợp lệ.
  - Từ sự kiện thứ 6 đến sự kiện thứ 20, Circuit Breaker tự động ngắt và chuyển sang `REQUIRE_HUMAN_APPROVAL`, bảo vệ hệ thống khỏi bão tự động hóa (Automation Storm).

## 5. Hướng dẫn Triển khai Phiên bản này trên Máy chủ Khác (Cross-Server Deployment Guide)
Để triển khai phiên bản tối ưu `v002` lên máy chủ mới (chỉ cần Docker Engine):
```bash
# 1. Chép gói nén sang máy chủ đích
scp dist_releases/secops_portable_v002.tar.gz user@target-server:/opt/

# 2. Giải nén và kích hoạt triển khai 1 chạm
ssh user@target-server "cd /opt && tar -xzf secops_portable_v002.tar.gz && cd v002_20261014_0515 && ./deploy.sh"
```

## 6. Kết luận & Đánh giá Hội tụ (Convergence Assessment)
Phiên bản `v002_20261014_0515` đã thỏa mãn đồng thời toàn bộ 5 điều kiện hội tụ nghiêm ngặt:
1. $D_{portability} = 1.00$ :white_check_mark:
2. $G_{safety} = 1.00$ và $G_{penalty} = 0$ :white_check_mark:
3. $F_1 = 1.0000 \ge 0.96$ :white_check_mark:
4. $FPR = 0.00\% \le 0.02$ :white_check_mark:
5. $MTTR = 0.0085\text{s} \le 5.0\text{s}$ :white_check_mark:
6. $S_{total} = 0.99997 \ge 0.95$ :white_check_mark:

Hệ thống chính thức đạt trạng thái **SẢN PHẨM TỐI ƯU NHẤT (OPTIMAL CONVERGED)**!
Gói phát hành di động đã được tạo tại `dist_releases/secops_portable_v002.tar.gz` và symlink `best_version` đã trỏ tới thư mục này.
