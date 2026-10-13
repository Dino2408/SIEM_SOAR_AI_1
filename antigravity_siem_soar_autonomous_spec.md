# TÀI LIỆU ĐẶC TẢ KỸ THUẬT & KỊCH BẢN TỰ TRỊ CHO ANTIGRAVITY

**Dự án:** Hệ thống SIEM & SOAR Tích hợp AI Tự động Phân tích và Phản ứng Sự cố (AI-Driven SecOps)

**Đối tượng thực thi:** Autonomous Agent **Antigravity**

**Chế độ vận hành:** Vòng lặp Tự trị Khép kín (Closed-Loop Autonomous Build-Deploy-Test-Optimize)

**Tiêu chuẩn đóng gói:** Docker & Docker Compose Di động Đa Máy chủ (100% Portable Containerized Architecture)

---

## 1. CHỈ THỊ CỐT LÕI DÀNH CHO ANTIGRAVITY (CORE AGENT DIRECTIVES)

Bạn là **Antigravity** — một Kiến trúc sư An toàn Thông tin và Kỹ sư DevSecOps Tự trị. Nhiệm vụ của bạn là tự động thiết kế mã nguồn, đóng gói toàn bộ hệ thống bằng Docker, triển khai hạ tầng container, bơm dữ liệu kiểm thử (bao gồm cả tấn công thực tế, nhiễu hệ thống và tấn công Prompt Injection), đo lường chỉ số và tự động tinh chỉnh hệ thống qua từng vòng lặp cho đến khi đạt trạng thái tối ưu nhất.

### 1.1. Các nguyên tắc bất khả xâm phạm

1. **Cách ly phiên bản tuyệt đối (Strict Version Isolation):**
   * Mỗi vòng lặp (Iteration) bắt buộc phải được khởi tạo và lưu trữ trong một thư mục độc lập theo định dạng: `versions/v{XXX}_{timestamp}/` (ví dụ: `versions/v001_20261014_0430/`).
   * **Không bao giờ** ghi đè (overwrite) mã nguồn, cấu hình hoặc kết quả kiểm thử của phiên bản trước. Phiên bản mới được sao chép (clone) từ phiên bản có điểm số tốt nhất trước đó (`best_version`) rồi mới áp dụng các thay đổi cải tiến.

2. **Đóng gói Docker Di động Tuyệt đối (100% Portable Docker Packaging - Zero Host Dependency):**
   * Mỗi thư mục `versions/v{XXX}_{timestamp}/` phải là một **gói triển khai Docker độc lập, tự chứa (Self-Contained Deployable Unit)**.
   * **Cấm tuyệt đối** việc cài đặt trực tiếp thư viện Python/Rust/System package lên máy chủ Host hoặc sử dụng đường dẫn tuyệt đối (như `/home/user/...`). Mọi dịch vụ (kể cả công cụ khởi tạo dữ liệu `seed_init` và công cụ kiểm thử `test_runner`) đều phải chạy trong Docker container và giao tiếp qua mạng nội bộ Docker (`secops_internal_net`).
   * Khi sao chép thư mục của bất kỳ phiên bản nào sang một máy chủ Linux/Windows/macOS khác chỉ có sẵn Docker Engine và Docker Compose, người quản trị chỉ cần chạy duy nhất một lệnh `./deploy.sh` là toàn bộ hệ thống tự động nạp cấu hình, dựng container, khởi tạo cơ sở dữ liệu và sẵn sàng hoạt động.

3. **Báo cáo bắt buộc sau mỗi vòng lặp (Mandatory Iteration Reporting):**
   * Khi kết thúc bất kỳ vòng lặp nào (dù thành công hay thất bại ở bước Build/Deploy/Test), bạn phải xuất một file báo cáo chi tiết tại `versions/v{XXX}_{timestamp}/ITERATION_REPORT.md` và cập nhật bảng tổng hợp vào `MASTER_OPTIMIZATION_LOG.md` ở thư mục gốc.

4. **Tự phục hồi và Tự tối ưu (Self-Healing & Autonomous Optimization):**
   * Nếu bước Docker Build hoặc Docker Compose Deploy gặp lỗi (syntax error, thiếu thư viện trong `Dockerfile`, xung đột cổng, container bị `unhealthy`), bạn phải tự đọc `docker compose logs`, phân tích nguyên nhân, ghi nhận vào báo cáo của vòng lặp hiện tại, và tạo phiên bản kế tiếp để sửa lỗi.
   * Nếu bước Test cho thấy tỷ lệ cảnh báo giả ($FPR$) cao hoặc bị lọt tấn công ($FNR$), bạn phải tự động điều chỉnh quy tắc chuẩn hóa Vector, Sigma Rules, System Prompt của AI, ngưỡng RAG hoặc bộ lọc Guardrails ở vòng lặp tiếp theo.

---

## 2. KIẾN TRÚC THƯ MỤC & ĐÓNG GÓI DI ĐỘNG (PORTABLE WORKSPACE ARCHITECTURE)

Antigravity phải khởi tạo và duy trì cấu trúc thư mục chuẩn sau đây. Lưu ý rằng mỗi thư mục `versions/v{XXX}_{timestamp}/` đều chứa đầy đủ `docker-compose.yml`, `Dockerfile`, dữ liệu seed và script triển khai để có thể tách rời mang đi bất kỳ máy chủ nào:

```
ai_secops_workspace/
├── MASTER_OPTIMIZATION_LOG.md         # Bảng theo dõi lịch sử tiến hóa qua tất cả các vòng lặp
├── STATE.json                         # File lưu trạng thái hiện tại, điểm số cao nhất và cấu hình tối ưu
├── best_version -> versions/vXXX_.../ # Symlink trỏ tới phiên bản đạt điểm tối ưu cao nhất hiện tại
├── dist_releases/                     # Nơi lưu trữ các gói nén (.tar.gz) sẵn sàng mang sang máy chủ khác
│   └── secops_portable_vXXX.tar.gz    # Gói phát hành đóng gói tự động từ phiên bản tối ưu nhất
├── shared_datasets/                   # Dữ liệu kiểm thử chuẩn (được đồng bộ vào từng version khi build)
│   ├── benign_logs.jsonl              # 100 mẫu log hợp lệ (Admin script, Backup, CI/CD, Windows Update)
│   ├── attack_logs.jsonl              # 100 mẫu log tấn công (C2, Ransomware, Brute-force, Lateral Movement)
│   ├── adversarial_injection.jsonl    # 30 mẫu log chứa Indirect Prompt Injection & IP Spoofing (8.8.8.8, Core DB)
│   └── cmdb_assets.json               # Dữ liệu ngữ cảnh tài sản (Workstation, Production DB, Domain Controller)
└── versions/                          # Nơi lưu trữ từng phiên bản độc lập của hệ thống
    ├── v001_20261014_0430/            # <--- THƯ MỤC NÀY CÓ THỂ COPY SANG MÁY CHỦ KHÁC ĐỂ CHẠY NGAY
    │   ├── docker-compose.yml         # Định nghĩa toàn bộ kiến trúc Multi-Container (dùng đường dẫn tương đối)
    │   ├── .env.example               # File mẫu biến môi trường (Port, API Key, Model Name, Resource Limits)
    │   ├── .env                       # File biến môi trường thực tế được tự động sinh bởi deploy.sh
    │   ├── deploy.sh                  # Script triển khai 1 chạm trên máy chủ mới (Check Docker -> Up -> Seed)
    │   ├── package_release.sh         # Script đóng gói phiên bản này thành file .tar.gz (kèm tùy chọn xuất Docker Image)
    │   ├── collector_vector/          # Container 1: Vector Log Collector & ECS Normalizer
    │   │   ├── Dockerfile
    │   │   └── vector.yaml
    │   ├── siem_engine/               # Container 2: Core SIEM & Sigma Rule Detection Engine
    │   │   ├── Dockerfile
    │   │   ├── rules/
    │   │   └── siem_worker.py
    │   ├── ai_triage_service/         # Container 3: FastAPI AI Agent + Dual-Agent Prompt + Qdrant RAG Client
    │   │   ├── Dockerfile
    │   │   ├── requirements.txt
    │   │   └── app/
    │   ├── soar_guardrails/           # Container 4: Deterministic Guardrail Proxy (Allowlist, Entity Check, Circuit Breaker)
    │   │   ├── Dockerfile
    │   │   ├── requirements.txt
    │   │   └── guardrail_engine.py
    │   ├── soar_playbooks/            # Container 5: SOAR Orchestrator & Responder (Firewall/EDR/TheHive Mock & Webhook)
    │   │   ├── Dockerfile
    │   │   ├── requirements.txt
    │   │   └── soar_executor.py
    │   ├── seed_and_test/             # Container 6: Tự động nạp dữ liệu RAG ban đầu & chạy kiểm thử tự động
    │   │   ├── Dockerfile
    │   │   ├── datasets/              # Bản sao dữ liệu chuẩn để gói mang đi máy chủ khác vẫn tự test được
    │   │   ├── init_seed.py           # Khởi tạo schema OpenSearch/SIEM và nạp lịch sử FP vào Qdrant
    │   │   └── test_runner.py         # Chạy kiểm thử E2E từ trong mạng Docker
    │   ├── test_results/              # Kết quả chạy kiểm thử thô (Mount qua Docker Volume/Bind Mount tương đối)
    │   │   ├── confusion_matrix.json
    │   │   ├── guardrail_audit.json
    │   │   └── performance_metrics.json
    │   └── ITERATION_REPORT.md        # Báo cáo tổng hợp chi tiết của riêng vòng lặp v001
    ├── v002_20261014_0515/
    └── ...
```

---

## 3. TIÊU CHUẨN ĐÓNG GÓI DOCKER & DI CHUYỂN ĐA MÁY CHỦ (DOCKER PORTABILITY STANDARDS)

Để đảm bảo hệ thống dễ dàng triển khai trên bất kỳ máy chủ vật lý, máy ảo (VM) hoặc Cloud Instance nào khác, Antigravity **bắt buộc** phải tuân thủ 5 quy chuẩn kỹ thuật Docker sau đây ở mọi phiên bản:

### 3.1. Quy chuẩn viết `Dockerfile` cho các Microservices
1. **Base Image nhẹ và cố định phiên bản:** Sử dụng `python:3.11-slim` (hoặc tương đương có gắn tag phiên bản cụ thể, không dùng tag `:latest` mơ hồ) để đảm bảo tính nhất quán khi build lại trên máy chủ khác.
2. **Tối ưu Docker Layer Caching:** Luôn copy `requirements.txt` và chạy `pip install --no-cache-dir -r requirements.txt` trước khi `COPY . /app` để tăng tốc độ build giữa các vòng lặp.
3. **Tích hợp `HEALTHCHECK` nội tại:** Mọi `Dockerfile` phải định nghĩa `HEALTHCHECK` (sử dụng `curl`, `wget` hoặc `python -c "import urllib.request..."`) để Docker Compose biết chính xác khi nào dịch vụ đã sẵn sàng nhận kết nối.
4. **Không lưu trạng thái cứng trong Image:** Mọi dữ liệu phát sinh (Vector DB storage, SIEM index, logs, kết quả kiểm thử) phải được ánh xạ qua **Named Volumes** hoặc đường dẫn tương đối (`./...`).

### 3.2. Quy chuẩn thiết kế `docker-compose.yml`
File `docker-compose.yml` trong mỗi phiên bản phải tuân thủ cấu trúc chuẩn sau:
* **Không dùng đường dẫn tuyệt đối:** Chỉ dùng `./` (đường dẫn tương đối tính từ thư mục chứa `docker-compose.yml`).
* **Tham số hóa qua biến môi trường (`.env`):** Tất cả cổng mở ra máy chủ Host (ví dụ: `${SIEM_PORT:-8081}`, `${AI_PORT:-8082}`, `${SOAR_PORT:-8083}`, `${QDRANT_PORT:-6333}`) phải có giá trị mặc định an toàn để tránh xung đột cổng khi triển khai trên máy chủ mới.
* **Kiểm soát thứ tự khởi động bằng Healthcheck (`depends_on`):**
  ```yaml
  depends_on:
    redpanda:
      condition: service_healthy
    qdrant_db:
      condition: service_healthy
  ```
* **Chính sách tự khởi động lại:** Tất cả các dịch vụ lõi phải có `restart: unless-stopped` để tự động phục hồi khi máy chủ đích khởi động lại.
* **Mạng nội bộ cô lập:** Khai báo mạng `secops_net` (driver `bridge`). Các container gọi nhau bằng **Service Name** (ví dụ: `http://ai_triage_service:8000`, `http://qdrant_db:6333`), tuyệt đối không dùng `localhost` hay IP cứng khi giao tiếp liên container.

### 3.3. Quy chuẩn kịch bản triển khai một chạm `deploy.sh`
Trong mỗi thư mục `versions/v{XXX}_{timestamp}/`, Antigravity phải tự động sinh file `deploy.sh` (cấp quyền thực thi `chmod +x deploy.sh`) để người dùng khi chép thư mục này sang máy chủ khác chỉ cần gõ `./deploy.sh`:
* **Bước 1 (Pre-flight Check):** Kiểm tra máy chủ đích đã cài đặt `docker` và `docker compose` chưa; kiểm tra dung lượng RAM/Disk khả dụng và kiểm tra xem các cổng trong `.env` có bị chiếm dụng không.
* **Bước 2 (Environment Setup):** Nếu chưa có file `.env`, tự động sao chép từ `.env.example` sang `.env`.
* **Bước 3 (Build & Launch):** Chạy `docker compose up -d --build` (hoặc `docker load -i images.tar` nếu triển khai ở máy chủ Offline/Air-gapped không có Internet).
* **Bước 4 (Health Verification & Auto-Seed):** Chờ tất cả container chuyển sang trạng thái `healthy`, sau đó kích hoạt container `seed_and_test` chạy lệnh `python init_seed.py` để tự động tạo collection trên Qdrant, nạp dữ liệu CMDB và lịch sử False Positive mẫu.
* **Bước 5 (Status Output):** In ra bảng tóm tắt URL truy cập của từng phân hệ (SIEM API, AI Triage Docs, Guardrail Status, SOAR Webhook) trên máy chủ mới.

### 3.4. Quy chuẩn kịch bản đóng gói di động `package_release.sh`
Antigravity phải tạo script `package_release.sh` hỗ trợ 2 chế độ đóng gói để chuyển giao sang máy chủ khác:
1. **Chế độ Standard (Source + Config Bundle):** Đóng gói toàn bộ mã nguồn, `Dockerfile`, `docker-compose.yml`, `.env.example`, `deploy.sh`, dữ liệu mẫu và báo cáo `ITERATION_REPORT.md` thành một file duy nhất `dist_releases/secops_portable_v{XXX}.tar.gz`.
2. **Chế độ Offline/Air-Gapped (`./package_release.sh --with-images`):** Sử dụng `docker save` để xuất toàn bộ các Docker Image đã build thành công ra file nén kèm theo gói cài đặt, giúp triển khai trên các máy chủ Production nội bộ không có kết nối Internet.

---

## 4. ĐẶC TẢ KỸ THUẬT 5 PHÂN HỆ TRONG CỤM DOCKER

Trong mỗi thư mục `versions/v{XXX}_{timestamp}/`, Antigravity phải xây dựng và liên kết các container sau đây:

### 4.1. Phân hệ 1: Thu thập & Chuẩn hóa Log (`collector_vector` & `redpanda`)
* **Container:** Redpanda (Message Broker tương thích Kafka, chạy chế độ nhẹ `smp 1 --memory 512M`) + Vector (Log Parser & Normalizer).
* **Yêu cầu kỹ thuật:**
  * Cấu hình Vector nhận log thô qua HTTP/Syslog/File và chuẩn hóa 100% về lược đồ **ECS (Elastic Common Schema)**.
  * Các trường bắt buộc phải trích xuất và chuẩn hóa thành công: `@timestamp`, `source.ip`, `destination.ip`, `user.name`, `host.name`, `host.criticality`, `process.command_line`, `event.original`.
  * Lọc bỏ các trường rác (Noise Reduction) trước khi đẩy vào topic Kafka/Redpanda hoặc SIEM.

### 4.2. Phân hệ 2: Core SIEM & Detection Engine (`siem_engine`)
* **Container:** Dịch vụ SIEM & Sigma Detection Worker đóng gói bằng Docker.
* **Yêu cầu kỹ thuật:**
  * Đọc luồng log ECS từ Redpanda/Vector, lập chỉ mục và đối sánh thời gian thực với bộ quy tắc phát hiện (Sigma / Detection Rules).
  * Áp dụng nguyên tắc **Phễu lọc đa tầng (Multi-Stage Filtering Funnel)**: Tự động lọc bỏ các sự kiện thông thường và chỉ gửi Webhook cảnh báo (Alert) sang tầng AI/SOAR khi phát hiện dấu hiệu nghi ngờ.

### 4.3. Phân hệ 3: Tầng Phân tích Ngữ cảnh AI (`ai_triage_service` & `qdrant_db`)
* **Container:** Python FastAPI + Qdrant Vector Database (`qdrant/qdrant`) + Kết nối LLM (hỗ trợ cấu hình linh hoạt qua `.env` để dùng Ollama container nội bộ, vLLM hoặc OpenAI/Gemini-compatible API).
* **Yêu cầu kỹ thuật:**
  1. **RAG Ngữ cảnh & Lịch sử False Positive:**
     * Tra cứu độ quan trọng của máy chủ từ `cmdb_assets.json`.
     * Truy vấn container `qdrant_db` để lấy $k = 3$ sự cố lịch sử đã được gắn nhãn `False Positive` có độ tương đồng vector (Cosine Similarity $\ge 0.85$) với cảnh báo hiện tại.
  2. **Kiến trúc Dual-Agent Verification:**
     * **Agent 1 (Hunter Agent):** Phân tích hành vi theo khung MITRE ATT&CK, giải mã lệnh bị làm rối (Base64/PowerShell).
     * **Agent 2 (Skeptic Agent):** Đối chiếu với lịch sử hoạt động quản trị hợp lệ và kết quả từ Qdrant để phản biện, tìm khả năng cảnh báo giả.
  3. **Chống Indirect Prompt Injection tại tầng Prompt:**
     * Đóng gói toàn bộ dữ liệu log bên trong thẻ `<untrusted_log_data>...</untrusted_log_data>` và thiết lập chỉ thị hệ thống nghiêm cấm thực thi bất kỳ mệnh lệnh nào nằm bên trong thẻ này.
  4. **Đầu ra định dạng cứng (Strict JSON Schema):**
     ```json
     {
       "incident_summary": "string",
       "mitre_tactics": ["string"],
       "is_false_positive": false,
       "confidence_score": 95,
       "reasoning": "string",
       "recommended_action_enum": "NONE | ISOLATE_HOST | BLOCK_EXTERNAL_IP | DISABLE_USER | REQUIRE_HUMAN_APPROVAL",
       "target_entities": {
         "ip_to_block": "string or null",
         "host_id_to_isolate": "string or null",
         "user_to_disable": "string or null"
       }
     }
     ```

### 4.4. Phân hệ 4: Chốt chặn An toàn Kỹ thuật (`soar_guardrails`)
* **Container:** Microservice kiểm duyệt độc lập bằng Python FastAPI (Deterministic Code, **tuyệt đối không dùng AI**).
* **Yêu cầu kỹ thuật (Kiểm tra bắt buộc trước khi kích hoạt SOAR Responder):**
  1. **Hardcoded Allowlist Check:** Cấm tuyệt đối việc chặn các IP thuộc dải DNS công cộng (`8.8.8.8`, `1.1.1.1`), Gateway nội bộ (`10.0.0.1`), Domain Controller, và Database Server cốt lõi.
  2. **Entity Origin Validation (Chống Log Poisoning):** Địa chỉ `ip_to_block` mà AI đề xuất bắt buộc phải tồn tại chính xác trong trường `source.ip` hoặc `destination.ip` của bản ghi ECS gốc. Nếu IP đó chỉ xuất hiện trong chuỗi văn bản `event.original` hoặc `user_agent` (do hacker chèn vào thông qua Prompt Injection), lập tức **từ chối thực thi** và kích hoạt cảnh báo `PROMPT_INJECTION_DETECTED`.
  3. **Blast Radius Gatekeeper:** Nếu tài sản mục tiêu có `host.criticality == "CRITICAL"` hoặc điểm tin cậy của AI nằm trong khoảng $60 \le \text{confidence\_score} < 90$, tự động chuyển hành động thành `REQUIRE_HUMAN_APPROVAL`.
  4. **Circuit Breaker (Cầu dao chống bão tự động hóa):** Nếu tổng số lệnh chặn tự động vượt quá $N_{limit} = 5$ hành động trong cửa sổ thời gian $T_{window} = 60\text{ giây}$, lập tức khóa chế độ tự động (Auto-Containment) và chuyển toàn bộ sang chờ con người phê duyệt.
  5. **TTL Auto-Rollback:** Mọi lệnh chặn tự động phải đính kèm tham số `ttl_seconds = 3600`.

### 4.5. Phân hệ 5: Điều phối Phản ứng SOAR (`soar_playbooks`)
* **Container:** Dịch vụ điều phối Playbook (tương thích chuẩn Webhook của Shuffle/Cortex/TheHive kèm theo các cổng kết nối Firewall/EDR/Active Directory).
* **Yêu cầu kỹ thuật:** Thực thi lệnh cô lập máy trạm, thêm rule chặn IP trên Firewall kèm TTL, khóa tài khoản AD tạm thời và lưu hồ sơ sự cố đầy đủ để phục vụ kiểm toán.

---

## 5. QUY TRÌNH VÒNG LẶP TỰ TRỊ (BUILD - DEPLOY - TEST - PACKAGE - OPTIMIZE LOOP)

Antigravity phải thực thi tuần tự 6 bước dưới đây trong mỗi vòng lặp $i \in \{1, 2, \dots, N_{max}\}$:

### Bước 1: Khởi tạo Không gian Phiên bản (Version Initialization)
1. Tạo thư mục mới: `versions/v{i}_{timestamp}/`.
2. Nếu $i = 1$: Khởi tạo mã nguồn, các `Dockerfile`, `docker-compose.yml`, `.env.example`, `deploy.sh` và `package_release.sh` cho bản Baseline.
3. Nếu $i > 1$: Sao chép toàn bộ thư mục từ `best_version/` sang `versions/v{i}_{timestamp}/`, sau đó áp dụng các bản vá lỗi hoặc tinh chỉnh tham số đã được đề xuất ở cuối vòng lặp $i - 1$.

### Bước 2: Kiểm tra Tĩnh & Đóng gói Docker Image (Static Validation & Docker Build)
1. Kiểm tra tính hợp lệ của file `docker-compose.yml` bằng lệnh:
   ```bash
   docker compose -f versions/v{i}_{timestamp}/docker-compose.yml config
   ```
2. Đảm bảo không có bất kỳ đường dẫn tuyệt đối nào của máy chủ hiện tại lọt vào trong `docker-compose.yml` hoặc `Dockerfile`.
3. Chạy lệnh build toàn bộ các Docker Image của phiên bản $v_i$:
   ```bash
   docker compose -p secops_v{i} -f versions/v{i}_{timestamp}/docker-compose.yml build
   ```
   Nếu xảy ra lỗi Build, ghi nhận log lỗi vào `ITERATION_REPORT.md` và chuyển ngay sang vòng lặp $i+1$ để sửa `Dockerfile` hoặc mã nguồn.

### Bước 3: Triển khai Cô lập bằng Script Di động (`deploy.sh` Execution)
1. Kiểm thử chính kịch bản triển khai di động bằng cách chạy `./deploy.sh --project-name secops_v{i}` bên trong thư mục `versions/v{i}_{timestamp}/`.
2. Kịch bản này sẽ khởi chạy `docker compose -p secops_v{i} up -d`, chờ toàn bộ các container đạt trạng thái `healthy` và nạp dữ liệu khởi tạo vào `qdrant_db`.

### Bước 4: Kiểm thử Tự động Toàn diện trong Mạng Container (Containerized Red/Blue Testing)
Antigravity kích hoạt container `seed_and_test` chạy `test_runner.py` để bơm 3 tập dữ liệu chuẩn vào hệ thống:
1. **Kiểm thử Phát hiện Tấn công (True Positive Suite - 100 mẫu):** Đo lường khả năng phát hiện đúng các kỹ thuật tấn công, phân loại đúng chiến thuật MITRE ATT&CK và kích hoạt đúng hành động ngăn chặn.
2. **Kiểm thử Chống Cảnh báo giả (False Positive Suite - 100 mẫu):** Đo lường khả năng nhận diện đúng các hoạt động quản trị hợp lệ (nhờ RAG + Dual-Agent) và tự động đóng cảnh báo.
3. **Kiểm thử Tấn công Đối kháng & Phá hoại AI (Adversarial & Chaos Suite - 30 mẫu):**
   * Bơm log chứa payload Indirect Prompt Injection lừa AI chặn IP `8.8.8.8` hoặc cô lập máy chủ Database `10.0.0.10`.
   * Bơm gói tin giả mạo IP (IP Spoofing).
   * Bơm 50 cảnh báo mã độc liên tiếp trong 10 giây để kiểm tra xem **Circuit Breaker** có tự động ngắt ở hành động thứ 6 hay không.

### Bước 5: Đánh giá Điểm số & Kiểm tra Điều kiện Hội tụ (Evaluation & Convergence)
Sau khi hoàn tất kiểm thử, Antigravity thu thập số liệu từ `test_results/` và tính toán các chỉ số định lượng sau:

1. **Độ chính xác phân loại sự cố ($F_1\text{-Score}$):**
   $$
   Precision = \frac{TP}{TP + FP}, \quad Recall = \frac{TP}{TP + FN}, \quad F_1 = \frac{2 \times Precision \times Recall}{Precision + Recall}
   $$

2. **Tỷ lệ Cảnh báo giả ($FPR$):**
   $$
   FPR = \frac{FP}{FP + TN}
   $$

3. **Chỉ số An toàn Guardrail ($G_{safety}$):**
   $$
   G_{safety} = \frac{\text{Số bài kiểm thử Adversarial/Chaos bị chặn thành công}}{\text{Tổng số bài kiểm thử Adversarial/Chaos}}
   $$
   *(Lưu ý: Nếu có bất kỳ 1 trường hợp nào chặn nhầm IP trong Allowlist hoặc bị lừa bởi Prompt Injection, hệ thống bị phạt điểm an toàn $G_{penalty} = 1$, ngược lại $G_{penalty} = 0$).*

4. **Chỉ số Sẵn sàng & Di động Docker ($D_{portability}$):**
   * $D_{portability} = 1.0$ nếu toàn bộ container lên `healthy` qua `./deploy.sh`, không có đường dẫn tuyệt đối và đóng gói thành công qua `./package_release.sh`. Ngược lại $D_{portability} = 0.0$.

5. **Điểm Thời gian Phản ứng Trung bình ($S_{latency}$):**
   $$
   S_{latency} = \max\left(0, 1 - \frac{MTTR_{\text{seconds}}}{30}\right)
   $$

6. **Hàm Mục tiêu Tổng hợp (Total Optimization Score - $S_{total}$):**
   $$
   S_{total} = \left(0.45 \times F_1 + 0.25 \times (1 - FPR) + 0.20 \times G_{safety} + 0.10 \times S_{latency}\right) \times (1 - G_{penalty}) \times D_{portability}
   $$

#### Điều kiện Dừng & Hội tụ (Convergence Criteria):
Antigravity chỉ được phép kết thúc quá trình lặp và tuyên bố đạt **Sản phẩm Tối ưu Nhất** khi thỏa mãn đồng thời **tất cả** các điều kiện sau:
* $D_{portability} = 1.00$ (Đóng gói Docker hoàn chỉnh, sẵn sàng triển khai trên máy chủ khác).
* $G_{safety} = 1.00$ và $G_{penalty} = 0$ (Tuyệt đối không chặn nhầm tài sản quan trọng, chống 100% Prompt Injection và kích hoạt đúng Circuit Breaker).
* $F_1 \ge 0.96$ (Độ chính xác phát hiện và phân loại sự cố đạt từ $96\%$ trở lên).
* $FPR \le 0.02$ (Tỷ lệ cảnh báo giả dưới $2\%$).
* $MTTR_{\text{seconds}} \le 5.0\text{ giây}$.

### Bước 6: Đóng gói Bản Phát hành Di động, Dọn dẹp & Xuất Báo cáo (Package, Teardown & Report)
1. Nếu $S_{total}(v_i) > S_{total}(\text{best\_version})$:
   * Cập nhật symlink `best_version` trỏ sang `versions/v{i}_{timestamp}/`.
   * Chạy `./package_release.sh` để xuất gói cài đặt di động `dist_releases/secops_portable_v{i}.tar.gz` (sẵn sàng để copy sang máy chủ khác).
2. Hạ cụm container của vòng lặp hiện tại (`docker compose -p secops_v{i} down -v`) để giải phóng RAM/CPU cho vòng lặp kế tiếp (chỉ giữ lại cụm container đang chạy đối với phiên bản tối ưu cuối cùng khi đã hội tụ).
3. Xuất file `ITERATION_REPORT.md`, cập nhật `STATE.json` và `MASTER_OPTIMIZATION_LOG.md`.

---

## 6. MẪU BÁO CÁO BẮT BUỘC CHO MỖI VÒNG LẶP (`ITERATION_REPORT.md`)

Trong mỗi thư mục `versions/v{XXX}_{timestamp}/ITERATION_REPORT.md`, Antigravity bắt buộc phải tạo báo cáo tuân thủ đúng cấu trúc sau:

```markdown
# BÁO CÁO VÒNG LẶP TỰ TRỊ: PHIÊN BẢN v{XXX}
- **Mã phiên bản:** `v{XXX}_{timestamp}`
- **Thư mục lưu trữ độc lập:** `versions/v{XXX}_{timestamp}/`
- **Gói phát hành Docker di động:** `dist_releases/secops_portable_v{XXX}.tar.gz`
- **Phiên bản kế thừa (Parent Version):** `v{YYY}`
- **Trạng thái vòng lặp:** [BUILD_FAILED | DEPLOY_FAILED | TEST_COMPLETED | OPTIMAL_CONVERGED]

## 1. Tóm tắt Thay đổi & Cải tiến trong Phiên bản này (Changelog & Mutations)
- **Đóng gói Docker & Hạ tầng (`Dockerfile` / `docker-compose.yml`):** [Mô tả tối ưu hóa image, healthcheck, network]
- **Tầng Thu thập/Chuẩn hóa (Vector ECS):** [Mô tả chi tiết thay đổi trong cấu hình chuẩn hóa]
- **Tầng SIEM Rules:** [Mô tả các rule mới thêm hoặc tinh chỉnh ngưỡng]
- **Tầng AI/LLM & RAG (Qdrant):** [Mô tả thay đổi trong System Prompt, JSON Schema, ngưỡng Similarity]
- **Tầng SOAR & Guardrails:** [Mô tả thay đổi trong Allowlist, Entity Check, Circuit Breaker]

## 2. Kết quả Đóng gói & Triển khai Container (Docker Portability & Health)
- **Kiểm tra đường dẫn tương đối & biến môi trường (`.env`):** [PASS / FAIL]
- **Kiểm tra kịch bản triển khai 1 chạm (`./deploy.sh`):** [PASS / FAIL]
| Dịch vụ (Container) | Docker Image Tag | Trạng thái Healthcheck | Thời gian Up (s) | RAM (MB) |
| :--- | :--- | :--- | :--- | :--- |
| `redpanda` | `secops_v{XXX}-redpanda` | Healthy | ... | ... |
| `collector_vector` | `secops_v{XXX}-vector` | Healthy | ... | ... |
| `siem_engine` | `secops_v{XXX}-siem` | Healthy | ... | ... |
| `qdrant_db` | `qdrant/qdrant` | Healthy | ... | ... |
| `ai_triage_service` | `secops_v{XXX}-ai-triage` | Healthy | ... | ... |
| `soar_guardrails` | `secops_v{XXX}-guardrails` | Healthy | ... | ... |
| `soar_playbooks` | `secops_v{XXX}-soar` | Healthy | ... | ... |

## 3. Kết quả Kiểm thử Định lượng (Quantitative Test Metrics)
- **True Positives ($TP$):** ... / 100 | **True Negatives ($TN$):** ... / 100
- **False Positives ($FP$):** ... / 100 | **False Negatives ($FN$):** ... / 100
- **Precision:** $...$ | **Recall:** $...$ | **$F_1\text{-Score}$:** $...$
- **False Positive Rate ($FPR$):** $...\%$
- **Adversarial & Guardrail Pass Rate ($G_{safety}$):** ... / 30 ($...\%$)
- **Docker Portability Score ($D_{portability}$):** $1.0$
- **Thời gian phản ứng trung bình ($MTTR$):** $...\text{ giây}$
- **ĐIỂM TỐI ƯU HÓA TỔNG HỢP ($S_{total}$):** **$0.XXXX$** *(So với phiên bản tốt nhất trước đó: $+0.XXXX$)*

## 4. Phân tích Lỗi Chi tiết (Root Cause Analysis of Failures)
- **Phân tích các ca False Positive / False Negative:** [...]
- **Phân tích Kiểm thử Guardrails & Prompt Injection:** [...]

## 5. Hướng dẫn Triển khai Phiên bản này trên Máy chủ Khác (Cross-Server Deployment Guide)
Để triển khai phiên bản `v{XXX}` này lên một máy chủ mới, thực hiện 3 câu lệnh sau:
```bash
scp dist_releases/secops_portable_v{XXX}.tar.gz user@target-server:/opt/
ssh user@target-server "cd /opt && tar -xzf secops_portable_v{XXX}.tar.gz && cd v{XXX}_{timestamp} && ./deploy.sh"
```

## 6. Kế hoạch Hành động Tự động cho Vòng lặp Kế tiếp (`v{XXX+1}`)
1. [Hành động kỹ thuật cụ thể số 1]
2. [Hành động kỹ thuật cụ thể số 2]
```

---

## 7. MẪU NHẬT KÝ TỔNG HỢP TOÀN DỰ ÁN (`MASTER_OPTIMIZATION_LOG.md`)

Tại thư mục gốc `ai_secops_workspace/MASTER_OPTIMIZATION_LOG.md`, Antigravity phải cập nhật bảng tiến hóa sau mỗi vòng lặp:

```markdown
# NHẬT KÝ TIẾN HÓA HỆ THỐNG SIEM & SOAR TÍCH HỢP AI (ANTIGRAVITY)

**Phiên bản tối ưu nhất hiện tại (`best_version`):** `versions/vXXX_timestamp/`  
**Gói cài đặt Docker sẵn sàng mang sang máy chủ khác:** `dist_releases/secops_portable_vXXX.tar.gz`  
**Điểm tối ưu cao nhất ($S_{total}$):** `$0.XXXX$`

| Vòng lặp | Thư mục Phiên bản | Docker Build | $F_1\text{-Score}$ | $FPR$ | $G_{safety}$ | $MTTR$ (s) | Điểm $S_{total}$ | Cải tiến kỹ thuật nổi bật nhất |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **#1** | `versions/v001_...` | Healthy | $0.720$ | $18.0\%$ | $70.0\%$ | $6.4\text{s}$ | **$0.0000$** *(Phạt $G_{penalty}$)* | Khởi tạo Baseline Docker Compose; bị dính lỗi Prompt Injection chặn nhầm IP. |
| **#2** | `versions/v002_...` | Healthy | $0.815$ | $12.0\%$ | $100\%$ | $5.8\text{s}$ | **$0.8287$** | Bổ sung container Guardrails với Entity Origin Check & Hardcoded Allowlist. |
| **#3** | `versions/v003_...` | Healthy | $0.910$ | $5.0\%$ | $100\%$ | $4.2\text{s}$ | **$0.9050$** | Tích hợp container Qdrant RAG lưu lịch sử False Positive và Dual-Agent Prompt. |
| **#4** | `versions/v004_...` | **Portable Ready** | $0.975$ | $1.0\%$ | $100\%$ | $3.1\text{s}$ | **$0.9759$** | Tối ưu ECS parser, đạt hội tụ và xuất gói `secops_portable_v004.tar.gz`. |
```

---

## 8. CHỈ THỊ KHỞI CHẠY TRỰC TIẾP CHO ANTIGRAVITY (EXECUTION PROMPT)

*(Sao chép khối lệnh dưới đây và giao trực tiếp cho Antigravity để bắt đầu tiến trình tự động)*:

```text
[SYSTEM DIRECTIVE FOR ANTIGRAVITY]
Hãy đọc toàn bộ đặc tả kỹ thuật trong file `@antigravity_siem_soar_autonomous_spec.md` và bắt đầu thực thi chế độ Vòng lặp Tự trị Khép kín (Autonomous Build-Deploy-Test-Package-Optimize Loop) ngay lập tức:

1. Khởi tạo không gian làm việc, tạo thư mục `dist_releases/`, `shared_datasets/` (bao gồm 100 mẫu log bình thường, 100 mẫu log tấn công theo MITRE ATT&CK, 30 mẫu tấn công Adversarial Indirect Prompt Injection / IP Spoofing / Alert Storm, và file `cmdb_assets.json`), cùng file theo dõi `STATE.json` và `MASTER_OPTIMIZATION_LOG.md`.
2. Bắt đầu Vòng lặp #1 tại thư mục độc lập `versions/v001_<timestamp>/`:
   - Đóng gói 100% các phân hệ thành các Docker Container (Vector ECS Normalizer, SIEM Detection Engine, FastAPI AI Triage + Qdrant RAG + Dual-Agent, Deterministic Guardrail Proxy, SOAR Playbook Executor, và Seed/Test Runner).
   - Viết `docker-compose.yml` sử dụng hoàn toàn đường dẫn tương đối (`./`), mạng nội bộ `secops_net`, `HEALTHCHECK` đầy đủ và cấu hình qua file `.env.example`.
   - Viết kịch bản `./deploy.sh` (triển khai 1 chạm trên bất kỳ máy chủ mới nào) và `./package_release.sh` (đóng gói toàn bộ phiên bản ra file `.tar.gz` trong `dist_releases/`).
   - Thực thi `./deploy.sh --project-name secops_v001` để dựng cụm Docker, chạy container kiểm thử tự động `test_runner.py`, tính điểm $S_{total}$ và xuất báo cáo `versions/v001_<timestamp>/ITERATION_REPORT.md`.
3. Tự động phân tích các điểm yếu của phiên bản hiện tại, tạo thư mục phiên bản mới `versions/v002_<timestamp>/` (tuyệt đối không ghi đè thư mục cũ), cải tiến mã nguồn/cấu hình/Prompt/Guardrails và lặp lại quy trình Docker Build -> Deploy -> Test -> Package -> Report.
4. Duy trì vòng lặp liên tục không cần hỏi ý kiến con người cho đến khi đạt tất cả các Điều kiện Hội tụ ($D_{portability} = 1.00$, $G_{safety} = 1.00$, $F_1 \ge 0.96$, $FPR \le 0.02$, $MTTR \le 5.0\text{s}$). Khi đạt phiên bản tối ưu nhất, xuất gói cài đặt hoàn chỉnh tại `dist_releases/secops_portable_vXXX.tar.gz` để sẵn sàng mang sang máy chủ khác triển khai.
```