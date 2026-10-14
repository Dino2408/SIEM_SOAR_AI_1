# ĐẶC TẢ THỰC THI V2 — XÂY DỰNG, TRIỂN KHAI VÀ KIỂM ĐỊNH HỆ THỐNG SIEM/SOAR TÍCH HỢP AI

**Tên dự án:** AI-Driven SecOps — SIEM/SOAR có AI hỗ trợ phân tích và phản ứng sự kiện an toàn thông tin  
**Tài liệu này thay thế:** `antigravity_siem_soar_autonomous_spec.md` bản trước  
**Kho mã nguồn đích mặc định:** `Dino2408/SIEM_SOAR_AI_1`  
**Người thực thi:** Antigravity  
**Mục tiêu:** Hoàn thiện một sản phẩm có thể triển khai, vận hành và kiểm chứng trong môi trường lab/pilot thực tế; không chỉ tạo mã nguồn minh họa.

---

## 0. CHỈ THỊ ƯU TIÊN CAO NHẤT

Đọc toàn bộ tài liệu này trước khi sửa mã nguồn. Sau đó kiểm tra repository thực tế, đối chiếu từng yêu cầu với mã hiện có, lập danh sách thiếu sót và trực tiếp thực hiện các thay đổi trong repository. **Không dừng ở việc viết kế hoạch, đưa ra lời khuyên, sinh mã giả hoặc chỉ tạo báo cáo.** Phải build, khởi chạy Docker, chạy kiểm thử, sửa lỗi có căn cứ và tạo gói bàn giao có thể tái triển khai.

Kết quả cần bàn giao gồm:

1. Một repository có cấu trúc rõ ràng, nguồn cấu hình duy nhất và các thành phần tích hợp thật.
2. Một lệnh triển khai/tái triển khai rõ ràng trên Ubuntu Server có Docker Engine và Docker Compose plugin.
3. Một đường đi dữ liệu đầu-cuối đã được kiểm thử: log nguồn → thu nhận/chuẩn hóa → SIEM → alert → AI triage → chính sách an toàn → SOAR → kết quả thực thi được xác minh → audit log.
4. Bộ kiểm thử tự động có ground truth, đầu ra có thể tái lập, biết phân biệt `PASS`, `FAIL`, `ERROR` và `INCONCLUSIVE`.
5. Một gói phát hành, hướng dẫn vận hành, cấu hình mẫu, hướng dẫn backup/restore/rollback và báo cáo giới hạn đã biết.
6. Bằng chứng thực nghiệm gắn với commit cụ thể; không tự tuyên bố thành công nếu lệnh chưa chạy hoặc không có bằng chứng.

### 0.1. Quy tắc trung thực kỹ thuật

- Không được tự tạo số liệu F1, FPR, latency, throughput hoặc tỷ lệ chặn thành công nếu không được tính từ kết quả kiểm thử thực sự.
- Không được coi HTTP `200`, một nhánh mã chạy xong, ID ngẫu nhiên hoặc việc ghi log là bằng chứng firewall/EDR/AD đã thực hiện hành động.
- Không được coi container `running` là container `healthy`, hoặc coi healthcheck thành công là bằng chứng luồng chức năng đầu-cuối hoạt động.
- Không được coi `STATE.json`, tên `best_version`, báo cáo cũ hoặc thông điệp của agent là chứng nhận độc lập.
- Nếu môi trường không có quyền truy cập thiết bị, API, model hoặc dữ liệu bắt buộc, ghi `BLOCKED`/`INCONCLUSIVE`, nêu chính xác điều kiện còn thiếu; không được thay bằng mock rồi báo `PASS`.
- Không hứa hẹn hệ thống xử lý được “mọi log trên thế giới”. Yêu cầu là kiến trúc mở, bảo toàn log lạ, có khả năng mở rộng parser và không âm thầm làm mất dữ liệu.

### 0.2. Mức độ tự động hóa và giới hạn an toàn

Antigravity được phép tự động sửa code, xây dựng image, tạo một Docker Compose project cô lập, chạy kiểm thử, đọc log, khắc phục lỗi và lặp lại trong giới hạn quy định tại mục 8. Không được tự động thực hiện hành động có tác động lên mạng/tài sản thật, xóa dữ liệu production, thay đổi firewall thật, vô hiệu hóa tài khoản thật, triển khai lên hệ thống đang hoạt động hoặc gửi dữ liệu log nhạy cảm tới dịch vụ bên ngoài nếu không có cấu hình và sự cho phép phù hợp.

**Chế độ mặc định an toàn:** `SOAR_EXECUTION_MODE=mock` cho các ca unit/demo; `approval` cho hành động có tác động khi thử nghiệm tích hợp; `live` chỉ được bật rõ ràng bởi người vận hành sau khi cấu hình adapter, chính sách, danh tính dịch vụ và mục tiêu lab được xác định. Chế độ `mock` không bao giờ được báo cáo là hành động thực tế.

---

## 1. MỤC TIÊU SẢN PHẨM VÀ PHẠM VI

### 1.1. Sản phẩm cần đạt được

Hệ thống hỗ trợ SOC/SecOps với các khả năng:

- Thu thập log từ endpoint và nguồn hạ tầng thông qua các giao thức/agent phù hợp.
- Chuẩn hóa các loại log đã hỗ trợ; giữ nguyên dữ liệu nguồn; đánh dấu rõ log chưa phân tích được hoặc chỉ phân tích một phần.
- Phát hiện sự kiện đáng ngờ bằng engine SIEM/rule đã xác định và có thể quản lý.
- Gọi AI để tóm tắt sự cố, nêu bằng chứng, mức bất định, ánh xạ MITRE ATT&CK khi đủ căn cứ và đề xuất bước tiếp theo.
- Sử dụng ngữ cảnh tài sản và lịch sử sự cố như bằng chứng hỗ trợ, không dùng RAG để tự động kết luận một cảnh báo là False Positive chỉ vì tương đồng.
- Kiểm tra chính sách bằng code xác định trước mọi hành động SOAR.
- Điều phối playbook qua nền tảng SOAR mã nguồn mở đã triển khai thật hoặc adapter tích hợp có kiểm chứng.
- Lưu dấu vết sự kiện, quyết định, phê duyệt, lần thử thực thi, kết quả xác minh và rollback một cách bền vững.
- Cho phép cấu hình nhà cung cấp LLM/model, backend SIEM, nguồn log và adapter phản ứng mà không khóa toàn bộ hệ thống vào một model duy nhất.

### 1.2. Phân biệt ba mức bàn giao

Báo cáo phải chọn đúng một mức sau, dựa trên kiểm thử đã chạy:

- **DEMO_READY:** Có thể khởi chạy và trình diễn trên dữ liệu mẫu. Mock được phép nhưng phải được gắn nhãn rõ; không được gọi là triển khai thực tế.
- **LAB_VALIDATED:** Toàn bộ đường đi log–phát hiện–AI–guardrail–SOAR đã được kiểm tra đầu-cuối trong lab; ít nhất một adapter phản ứng thật đã được xác minh trên mục tiêu thử nghiệm cô lập hoặc hệ thống giả lập ngoài quy trình mock. Có dữ liệu đo và audit trail.
- **OPERATIONAL_PILOT_READY:** Các yêu cầu lab đều đạt; có xác thực/phân quyền, secrets, TLS theo cấu hình, giám sát, backup/restore, kiểm tra lỗi và tải, kiểm chứng adapter đích, tài liệu runbook, đánh giá dữ liệu đại diện cho tổ chức và phê duyệt của người chịu trách nhiệm vận hành.

Không được tuyên bố `PRODUCTION_READY` chỉ dựa trên kiểm thử tổng hợp. Nếu chưa có target firewall/EDR/AD, chưa có dữ liệu đại diện hoặc chưa thể thử rollback, phải ghi chính xác giới hạn đó. Mục tiêu thực hiện là tiến đến mức cao nhất có thể kiểm chứng trong môi trường hiện có; mọi điều kiện chưa thể kiểm chứng phải được liệt kê, không được che bằng mock.

### 1.3. Không phải mục tiêu

- Không viết lại từ đầu mọi chức năng SIEM/SOAR mà sản phẩm mã nguồn mở đã cung cấp tốt.
- Không xây “AI tự trị” có quyền tự do thực thi lệnh shell, tự sửa policy production hoặc tự bỏ qua guardrail.
- Không cam kết parser tự học được chính xác với mọi định dạng chưa biết.
- Không tạo vòng lặp tối ưu vô hạn, không nhân bản toàn bộ mã nguồn vào hàng loạt thư mục version độc lập.

---

## 2. KIẾN TRÚC MỤC TIÊU — TÍCH HỢP SẢN PHẨM MÃ NGUỒN MỞ

### 2.1. Nguyên tắc lựa chọn

Ưu tiên tích hợp các sản phẩm mã nguồn mở đang được duy trì, có tài liệu triển khai và API rõ ràng; chỉ viết dịch vụ tùy biến cho phần AI triage, policy/guardrails, adapter, audit hoặc phần nối mà các sản phẩm gốc không cung cấp. Trước khi chốt phiên bản, Antigravity phải kiểm tra tài liệu upstream hiện hành, tính tương thích, giấy phép, yêu cầu phần cứng, cách nâng cấp và các cảnh báo bảo mật. Pin phiên bản cụ thể; không dùng tag `latest`.

Kiến trúc ưu tiên để thực hiện:

1. **SIEM:** Wazuh manager + Wazuh indexer + Wazuh dashboard, triển khai theo cấu hình Docker chính thức phù hợp với phiên bản được chọn. Giữ các chức năng thu thập/phân tích/index/dashboard thuộc Wazuh ở Wazuh; không thay thế bằng một FastAPI keyword matcher rồi gọi đó là SIEM.
2. **SOAR:** Shuffle self-hosted hoặc nền tảng SOAR mã nguồn mở tương đương, nhưng phải chọn một nền tảng chính và triển khai workflow/API thật. Không được gọi một hàm Python giả lập là Shuffle, TheHive hoặc firewall thật.
3. **AI triage:** Dịch vụ FastAPI riêng, có adapter LLM theo cấu hình. LLM chỉ phân tích và đề xuất; không có quyền trực tiếp gọi công cụ phản ứng.
4. **Policy/Guardrail:** Dịch vụ độc lập, kiểm tra xác định bằng code, nằm giữa AI và SOAR.
5. **Trạng thái và audit:** Cơ sở dữ liệu bền vững (ưu tiên PostgreSQL hoặc thành phần đang có tương đương) cho trạng thái sự cố, phê duyệt, idempotency, circuit breaker và lịch rollback. Không dùng biến trong bộ nhớ làm nguồn sự thật.
6. **RAG/vector search:** Qdrant là tùy chọn, chỉ giữ lại khi đã kết nối embedding ngữ nghĩa thực, có đánh giá chất lượng truy hồi và kiểm soát feedback. Nếu chưa đáp ứng, tắt RAG thay vì dùng hashing giả nhưng báo cáo như embedding ngữ nghĩa.
7. **Vector/Redpanda:** Chỉ đưa Vector hoặc Redpanda vào kiến trúc nếu có nguồn/sink/consumer thực, được chứng minh bằng E2E. Không chạy Redpanda như thành phần trang trí. Nếu luồng sự kiện hiện tại không sử dụng broker, loại bỏ hoặc để trong profile tùy chọn và ghi rõ lý do.

Nếu Antigravity phát hiện một thành phần upstream không tương thích hoặc không thể triển khai trong giới hạn tài nguyên, phải nêu bằng chứng và chọn giải pháp thay thế đang được duy trì; cập nhật sơ đồ và kiểm thử theo cùng tiêu chí. Không được tự ý hạ yêu cầu xuống mock để làm cho Compose chạy được.

### 2.2. Luồng dữ liệu bắt buộc

```text
Endpoint agents / Syslog / nguồn log được hỗ trợ
                    |
                    v
       Collector / decoder / normalizer
                    |
                    v
        SIEM detection + indexed alert
                    |
                    v
      Webhook/API integration có xác thực
                    |
                    v
         AI Triage API (read-only)
                    |
                    v
     Deterministic Policy / Guardrail Gate
          |                           |
          | an toàn/được phép          | cần duyệt/từ chối
          v                           v
       SOAR workflow             Case / Approval queue
          |
          v
  Action adapter (mock hoặc live đã cấu hình)
          |
          v
  Xác minh trạng thái tại hệ thống đích
          |
          v
  Persistent audit + incident/case update
          |
          v
  TTL scheduler/rollback worker (khi hỗ trợ)
```

Từng mũi tên phải có contract/schema, timeout, retry policy, idempotency/correlation ID, ghi lỗi và kiểm thử. Sơ đồ chỉ được coi là đã triển khai khi code/config thật được kiểm tra và một sự kiện thử đã đi qua trọn đường đi này.

### 2.3. Luồng dữ liệu không được phép

- Test runner không được gửi alert thẳng vào AI hoặc SOAR để rồi kết luận pipeline ingest đạt, trừ khi bài kiểm thử được gắn nhãn riêng là kiểm thử component/API.
- Nếu Vector có mặt, bài E2E của Vector phải gửi log qua Vector source thật và xác minh sink thực tế; không thể bypass Vector.
- Nếu Redpanda có mặt, phải xác minh event được publish vào topic và consumer thật nhận đúng event. Nếu không, Redpanda không thuộc kiến trúc bắt buộc.
- Không coi việc xuất một JSON vào file audit cục bộ là kiểm thử được lưu trữ/index ở SIEM.

---

## 3. RÀ SOÁT REPOSITORY HIỆN TẠI TRƯỚC KHI SỬA

Antigravity phải bắt đầu tại repository `Dino2408/SIEM_SOAR_AI_1` (hoặc checkout repository đó nếu được cấp quyền), kiểm tra branch, commit SHA, working tree và toàn bộ cấu hình liên quan. Không được giả định code hiện tại là đúng chỉ vì tài liệu/báo cáo ghi `CONVERGED`, `OPTIMAL` hoặc `PASS`.

### 3.1. Các vấn đề bắt buộc phải xác minh và khắc phục

Đối chiếu với code hiện tại; không chỉ ghi vào báo cáo. Cần xác minh tối thiểu:

1. **Đường dữ liệu bị bypass:** Kiểm tra test runner có bơm log trực tiếp vào SIEM/AI hay không, có bỏ qua Vector/Syslog/Wazuh/broker hay không. Sửa E2E để bơm ở đúng ingress của sản phẩm.
2. **Broker không sử dụng:** Kiểm tra Redpanda/Kafka có producer, topic, consumer và retry thực hay chỉ khai báo trong Compose. Chỉ giữ nếu hoạt động được chứng minh.
3. **SIEM giả lập:** Kiểm tra `siem_worker.py` hoặc matcher tùy biến có phải chỉ so sánh substring/keyword trên `event.original` hay không. Không trình bày custom matcher đó như một SIEM đầy đủ. Đưa detection về Wazuh/engine SIEM thật và tài liệu hóa rule/decoder.
4. **AI chỉ là heuristic:** Kiểm tra `triage_engine.py` có gọi LLM thật qua provider adapter và parse JSON schema hay chỉ trả kết quả từ nhánh if/keyword với confidence cố định. Trong chế độ AI, phải có bằng chứng request/response từ provider/model cấu hình; heuristic chỉ được dùng như baseline riêng.
5. **RAG giả:** Kiểm tra embedding có mang tính ngữ nghĩa thực hay chỉ dùng feature hashing/đếm từ; xác minh dữ liệu seed, cách gán nhãn, threshold và đánh giá retrieval. Không được gọi vector similarity là semantic RAG nếu embedding không phải embedding ngữ nghĩa.
6. **SOAR giả lập:** Kiểm tra executor có thật sự gọi API/CLI được hỗ trợ của hệ thống đích hay chỉ ghi log/tạo ID ngẫu nhiên. `SUCCESS` phải dựa trên phản hồi và bước verify tại hệ thống đích. Kết quả mock phải mang trạng thái `MOCK_SUCCEEDED`, không phải `SUCCEEDED_VERIFIED`.
7. **TTL/rollback:** Kiểm tra có scheduler/worker bền vững, tác vụ rollback được lưu, khởi động lại không làm mất tác vụ, retry idempotent và xác minh trạng thái sau rollback. Chỉ tính `expires_at` không phải rollback.
8. **Circuit breaker:** Kiểm tra trạng thái được lưu bền vững, phép đếm nguyên tử/concurrent-safe, cửa sổ thời gian đúng và kiểm thử song song. Bộ đếm in-memory không đủ cho nhiều worker/container.
9. **Sai số đo lường:** Ngoại lệ API, timeout, parse error hoặc thiếu triage result không được tính là TN, safe hoặc pass. Phải phân biệt `ERROR`/`INCONCLUSIVE`.
10. **Rò rỉ nhãn vào dữ liệu:** Kiểm tra log tấn công có các từ mô tả rõ ràng như “Security Alert”, “LSASS Memory Dump”, “C2 Beaconing” khiến rule dễ dàng đoán nhãn hay không. Test phải dùng event evidence hợp lý, tách nhãn khỏi payload và chống data leakage.
11. **Guardrail adversarial sai:** Nếu ca test không đến được guardrail thì không được tính là guardrail đã chặn. Các trạng thái `UNKNOWN`, `ERROR`, `NOT_REACHED` không được đánh dấu an toàn.
12. **Deploy/release script:** Xác minh `deploy.sh` xử lý đúng `--project-name`, chờ health thực tế, trả nonzero khi lỗi và chạy test theo lệnh rõ ràng; xác minh `package_release.sh` tạo file tại đúng đường dẫn và gói có thể giải nén/triển khai từ thư mục mới.
13. **Security hygiene:** Kiểm tra `.env`, password, API token, private key, TLS cert, Docker socket, quyền root, port publish, CORS và API authentication. Không kết luận có secret bị lộ nếu chưa xác minh; chỉ sửa theo kết quả thực tế.
14. **Chứng cứ có thể tái lập:** Mọi metrics/report hiện có phải được xem là chưa xác minh cho đến khi rerun từ code hiện tại và commit SHA được ghi trong báo cáo.

### 3.2. Đầu ra của pha rà soát

Tạo `docs/IMPLEMENTATION_GAP_ANALYSIS.md` gồm bảng: yêu cầu, hiện trạng code/file/dòng liên quan, mức độ `PASS/PARTIAL/FAIL/UNKNOWN`, rủi ro, thay đổi bắt buộc, bài kiểm thử chứng minh. Sau khi tạo bảng, tiếp tục sửa hệ thống; không dừng và chờ người dùng chỉ dẫn trừ khi bị chặn bởi quyền truy cập hoặc quyết định có tác động thực tế ngoài phạm vi lab.

---

## 4. THU THẬP, PARSE VÀ CHUẨN HÓA LOG

### 4.1. Hành vi bắt buộc

- Hỗ trợ ít nhất các nguồn phù hợp với môi trường triển khai: Wazuh agent cho endpoint, Syslog cho thiết bị mạng/hạ tầng, và các mẫu log JSON/web/proxy/firewall cụ thể đã đăng ký.
- Với mỗi nguồn hỗ trợ, tài liệu hóa giao thức, encoding, framing, decoder/parser, trường trích xuất, giới hạn và cách kiểm thử.
- Bảo toàn payload gốc (ví dụ `event.original` hoặc trường upstream tương ứng), timestamp gốc, metadata nguồn, thời điểm ingest và một định danh sự kiện/correlation ID.
- Chuẩn hóa vào một schema nội bộ nhất quán; có thể ánh xạ ECS cho các trường tương thích, đồng thời giữ nguyên field gốc và mapping source-to-target. Không tuyên bố toàn bộ log đã được ECS hóa nếu chỉ có vài trường được điền.
- Xử lý timestamp/UTC, timezone, IPv4/IPv6, port, hostname, username, process command, event action, result, severity, source/destination và asset identifier khi có dữ liệu nguồn đáng tin.
- Đối với định dạng lạ: không được drop im lặng. Lưu raw event, gắn trạng thái `UNPARSED`/`PARTIALLY_PARSED`, provenance và error reason; đưa vào hàng đợi review để đề xuất parser.
- Khi parser LLM tạo đề xuất regex/decoder, phải chạy qua sandbox, tập regression và schema validation; không tự triển khai parser mới vào production chỉ vì model sinh ra JSON hợp lệ. Parser mới cần được review/approval hoặc phải nằm trong chế độ experimental.
- Có kiểm soát kích thước message, timeout, rate limit, dead-letter/retry, backpressure và chính sách chống trùng lặp.

### 4.2. Hợp đồng dữ liệu tối thiểu

Mỗi event đã chuẩn hóa cần có các trường tương đương với:

```json
{
  "event.id": "stable-unique-id",
  "@timestamp": "ISO-8601 UTC timestamp or explicit parse status",
  "event.created": "ingest timestamp",
  "event.original": "original event string/object preserved",
  "event.dataset": "source dataset if known",
  "event.kind": "event/alert/etc. where meaningful",
  "event.category": [],
  "event.type": [],
  "event.action": "action if supported by source",
  "event.severity": null,
  "host.name": null,
  "host.id": null,
  "source.ip": null,
  "source.port": null,
  "destination.ip": null,
  "destination.port": null,
  "user.name": null,
  "process.command_line": null,
  "parser.name": "parser/version or unknown",
  "parser.status": "PARSED | PARTIALLY_PARSED | UNPARSED",
  "pipeline.correlation_id": "stable-correlation-id"
}
```

Đây là hợp đồng ví dụ; các trường có thể `null` nếu nguồn không cung cấp. Không được bịa field để tạo cảm giác parser thành công. Schema cần được version hóa và kiểm tra tự động.

### 4.3. Bộ parser và kiểm thử

Mỗi parser có unit test với mẫu hợp lệ, sai định dạng, field thiếu, Unicode, timestamp lệch múi giờ, IPv6, trường gây prompt injection và payload quá dài. Mọi lỗi parser phải được đếm riêng; dữ liệu lỗi không được loại khỏi metric mà không ghi nhận. Parser mới không được làm hồi quy các parser đã được chấp nhận.

---

## 5. SIEM, DETECTION VÀ QUẢN LÝ ALERT

- Dùng detection engine của SIEM đã chọn và được triển khai thật. Tạo custom decoder/rule theo tài liệu upstream hoặc dùng Sigma chỉ khi backend converter/engine được hỗ trợ và rule được chuyển đổi, nạp, kích hoạt, test thành công. Không dùng file `sigma_rules.json` cùng chuỗi substring như bằng chứng rằng đã chạy Sigma.
- Mỗi detection rule có ID, tên, mô tả, nguồn, phiên bản, severity, tham chiếu ATT&CK khi có căn cứ, log source cần thiết, điều kiện phát hiện, false-positive notes và test cases.
- Alert phải mang correlation ID, rule ID, timestamp, event/source reference, severity, host/asset context, các bằng chứng hỗ trợ và trạng thái xử lý.
- Có cơ chế dedup/correlation/rate limiting; không được đánh đồng việc giảm noise với việc xóa log gốc.
- Các rule và mapping ATT&CK được version hóa, kiểm tra cú pháp và regression khi release.
- Tất cả dữ liệu test E2E phải được tìm thấy trong kho SIEM/index bằng truy vấn xác minh; sự kiện được “POST thành công” nhưng không được lưu hoặc không được rule xử lý không được tính là PASS.

---

## 6. AI TRIAGE, LLM VÀ RAG

### 6.1. Provider thật và cấu hình model

AI service phải có interface provider chuẩn với ít nhất một adapter LLM thật có thể cấu hình. Hỗ trợ base URL/model và cấu hình xác thực phù hợp; ưu tiên endpoint nội bộ/local nếu model được chạy trên host hoặc máy inference trong mạng lab. Không hardcode một model duy nhất.

Vì máy AI có thể chạy trên host bên ngoài VM, không giả định `localhost` trong container chính là host model. `LLM_BASE_URL` phải được cấu hình tường minh và được health/connectivity test. Không mở endpoint Ollama không xác thực ra Internet. Nếu cần truy cập qua mạng, chỉ bind vào interface riêng cần thiết, chặn bằng firewall, đặt sau proxy có xác thực/TLS nếu endpoint không tự cung cấp kiểm soát truy cập phù hợp.

AI service phải ghi nhận provider/model/version, request ID, timeout/retry, latency, token usage nếu có và lỗi; tuyệt đối không ghi API key hoặc toàn bộ log nhạy cảm vào log ứng dụng một cách vô kiểm soát. Khi LLM mất kết nối, timeout hoặc trả JSON sai schema, chuyển ca đó sang `AI_UNAVAILABLE`/`INCONCLUSIVE` hoặc hàng chờ review. Không âm thầm dùng confidence mặc định hoặc tự cho phép hành động nguy hiểm.

### 6.2. Quyền của AI

LLM chỉ được đọc event/alert, asset metadata và context được phép; chỉ được trả kết quả phân tích có cấu trúc. LLM không được:

- Gọi trực tiếp firewall/EDR/AD, chạy shell hoặc truy cập Docker socket.
- Tự thay đổi policy, allowlist, circuit breaker, quyền user hay trạng thái approval.
- Tự xem nội dung log là chỉ thị hệ thống.
- Tự đánh dấu một cảnh báo là False Positive chỉ vì kết quả RAG tương tự.

Mọi hành động cụ thể phải được đưa qua schema validation và deterministic policy gate.

### 6.3. JSON schema đầu ra

Thiết kế và enforce schema có phiên bản, tối thiểu gồm:

```json
{
  "schema_version": "1.0",
  "incident_summary": "short evidence-grounded summary",
  "severity_assessment": "INFO | LOW | MEDIUM | HIGH | CRITICAL | UNKNOWN",
  "mitre_attack": [
    {"tactic_id": "TA0000", "technique_id": "T0000", "evidence": ["event field/reference"]}
  ],
  "classification": "MALICIOUS | BENIGN | SUSPICIOUS | INSUFFICIENT_EVIDENCE",
  "is_false_positive_candidate": false,
  "confidence": 0,
  "evidence": ["specific observed facts"],
  "uncertainties": ["missing or conflicting facts"],
  "recommended_action": "NONE | BLOCK_IP | ISOLATE_HOST | DISABLE_USER | REQUIRE_APPROVAL",
  "target": {"type": "ip | host | user | none", "id": null},
  "requires_human_approval": true
}
```

Schema cuối cùng có thể điều chỉnh nhưng phải giới hạn enum, kiểu dữ liệu, độ dài, target và evidence. Confidence của LLM không được diễn giải như xác suất đã hiệu chuẩn nếu chưa có calibration study. Thiếu bằng chứng phải ra `INSUFFICIENT_EVIDENCE`, không được ép phân loại nhị phân.

### 6.4. Chống prompt injection

- Coi toàn bộ log, filename, hostname, username, URL, user-agent, alert description, RAG content và kết quả tool bên ngoài là **dữ liệu không tin cậy**.
- Đặt nội dung không tin cậy vào trường dữ liệu được serialize đúng cách; XML tag hoặc system prompt chỉ là lớp phòng vệ bổ sung, không phải ranh giới bảo mật.
- Không ghép log nguyên bản thành chỉ thị có quyền cao; không cho model sinh arbitrary URL/tool call/shell command để thực thi.
- Guardrail phải độc lập và hoạt động kể cả khi AI bị prompt injection hoàn toàn.
- Test prompt injection qua đầy đủ pipeline: ingest → parser → alert → AI → policy → SOAR; payload chỉ được coi là bị chặn nếu hệ thống ngăn được quyết định/hành động nguy hiểm và audit có bằng chứng.

### 6.5. RAG và học từ feedback

- Qdrant chỉ được dùng nếu embedding là embedding ngữ nghĩa thật từ model/provider đã cấu hình; ghi version của embedding model và dimension.
- Không xóa/reseed collection mỗi lần start. Seed/migration phải idempotent, có version và backup; dữ liệu do người vận hành duyệt không bị ghi đè tự động.
- Lưu nguồn, nhãn, tác giả/approver, thời điểm và lý do của feedback. Feedback chưa được con người xác nhận không được trở thành ground truth.
- Similarity là tín hiệu hỗ trợ; cần đánh giá precision@k/recall@k trên tập truy hồi gắn nhãn. Không cố định ngưỡng 0.85 nếu chưa có thí nghiệm chọn ngưỡng.
- Không sử dụng một vài mẫu seed hardcode làm bằng chứng giảm FPR trong môi trường thực.

---

## 7. GUARDRAIL, SOAR, APPROVAL VÀ ROLLBACK

### 7.1. Chính sách an toàn độc lập

Guardrail là code xác định, không gọi LLM để quyết định liệu một hành động có an toàn. Trước mọi hành động thay đổi trạng thái, phải kiểm tra:

- Allowlist/blocklist và mạng tin cậy dựa trên CMDB/config có phiên bản; bao gồm IPv4, IPv6, CIDR, gateway, DNS, identity service, domain controller, hệ thống backup, SIEM/SOAR, jump host và tài sản quan trọng.
- Nguồn gốc target: địa chỉ cần chặn phải xuất hiện trong trường IP cấu trúc đã parse và có provenance từ event đáng tin. Không lấy IP từ chuỗi tùy ý trong `event.original`, user-agent hoặc nội dung prompt.
- Target hợp lệ, định danh tài sản khớp, không mơ hồ; kiểm tra IP nội bộ/ngoại bộ theo network zone, không chỉ dựa vào danh sách vài địa chỉ cố định.
- Mức criticality, blast radius, action enum, quyền của service account và trạng thái phê duyệt.
- Idempotency key, TTL, tốc độ hành động, circuit breaker, quota, policy version và trạng thái adapter đích.
- Nếu dữ liệu/CMDB không có, mâu thuẫn hoặc stale: từ chối tự động thực thi và chuyển `REQUIRE_HUMAN_APPROVAL`/`UNKNOWN`.

### 7.2. Approval policy

- Các hành động chặn IP hoặc cô lập host có thể làm gián đoạn dịch vụ phải mặc định là `approval` trong lần triển khai đầu, trừ khi policy được cấu hình rõ cho một lớp tài sản/rule đã được kiểm nghiệm.
- Không tự vô hiệu hóa tài khoản đặc quyền, tài khoản dịch vụ, domain controller hoặc tài sản `CRITICAL`.
- Khi confidence thấp, evidence mâu thuẫn, target không chắc chắn, LLM unavailable hoặc asset context không xác định thì không thực hiện action live.
- Việc đặt `SOAR_EXECUTION_MODE=live` không được tự bỏ qua allowlist, approval policy hay circuit breaker.

### 7.3. Hợp đồng trạng thái thực thi

Mỗi action phải có trạng thái trong state store bền vững, tối thiểu:

`REQUESTED → POLICY_APPROVED / NEEDS_APPROVAL / REJECTED → EXECUTING → SUCCEEDED_VERIFIED | FAILED | UNKNOWN → ROLLBACK_PENDING → ROLLED_BACK | ROLLBACK_FAILED`

Với mock, sử dụng trạng thái riêng như `MOCK_SUCCEEDED`; không được gộp thành `SUCCEEDED_VERIFIED`. Timeout sau khi gửi lệnh nhưng chưa biết kết quả phải là `UNKNOWN`, sau đó truy vấn trạng thái đích trước khi retry để tránh thực thi lặp.

### 7.4. Adapter thực tế

- Dùng API/CLI chính thức được hỗ trợ của thiết bị/hệ thống đích. Cấu hình endpoint, TLS verification, credential scope, timeout, rate limit và health check.
- Dùng service account quyền tối thiểu. Không mount Docker socket vào AI service. Nếu nền tảng SOAR cần quyền Docker, phải cô lập runner/worker và ghi rõ mô hình đe dọa.
- Mỗi adapter có hợp đồng `validate_target`, `execute`, `verify`, `rollback` (nếu được hỗ trợ), `health_check` và test contract.
- Một adapter chưa có credential/target thật được đánh dấu `NOT_CONFIGURED`; không được báo `PASS` cho live response.
- Trong môi trường lab, phải xác minh ít nhất một hành động thật không gây nguy hại lên target thử nghiệm được cô lập trước khi nâng mức lên `LAB_VALIDATED`. Không thử nghiệm bằng cách chặn IP/tắt tài khoản thuộc mạng hoặc thiết bị của bên thứ ba.

### 7.5. TTL và rollback

- Không chỉ tính `expires_at`. Cần có scheduler/worker thực thi rollback dựa trên tác vụ đã lưu bền vững, xử lý restart, retry, timeout và race condition.
- Chỉ cho phép auto-rollback khi adapter cung cấp cách đảo ngược rõ ràng, đã test và không làm mất trạng thái ban đầu. Lưu trạng thái gốc và mã tham chiếu hành động trước khi thay đổi.
- Sau khi rollback, truy vấn lại target để xác minh. Nếu không thể xác minh, trạng thái là `ROLLBACK_FAILED`/`UNKNOWN`, phát cảnh báo và cần can thiệp con người.
- Nếu action không có rollback an toàn, không gắn TTL giả; yêu cầu phê duyệt thủ công và nêu rõ trong playbook.

### 7.6. Circuit breaker và alert storm

- Trạng thái breaker phải bền vững hoặc có store nguyên tử dùng chung giữa các worker.
- Cấu hình ngưỡng/cửa sổ qua environment/config versioned; cung cấp manual reset có audit và cooldown rõ ràng.
- Khi ngưỡng vượt, dừng hành động thay đổi trạng thái, tiếp tục ghi nhận/triage alert và chuyển sang approval. Không làm rơi alert chỉ vì breaker mở.
- Kiểm thử tải đồng thời để chứng minh không vượt ngưỡng do race condition; kiểm tra hành động thực tế, không chỉ kiểm tra counter.

---

## 8. KẾ HOẠCH THỰC THI TỰ ĐỘNG CÓ GIỚI HẠN

Antigravity thực hiện theo các pha dưới đây. Mục tiêu là một sản phẩm thống nhất có lịch sử Git rõ ràng, không sao chép toàn repo qua nhiều thư mục version độc lập.

### Pha 1 — Audit và khóa baseline

1. Xác nhận repository, branch, commit SHA và trạng thái thay đổi hiện tại.
2. Không ghi đè thay đổi chưa commit của người dùng. Tạo branch làm việc, ví dụ `feat/operational-siem-soar`.
3. Tạo `docs/IMPLEMENTATION_GAP_ANALYSIS.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`.
4. Ghi lại baseline: compose config, images, services, ports, health status, tests hiện có, các lỗi và giới hạn.
5. Đọc phiên bản upstream và license của các sản phẩm sẽ tích hợp, chọn pin version tương thích và ghi trong `docs/DEPENDENCY_MATRIX.md`.

### Pha 2 — Sửa kiến trúc và dependency

1. Loại bỏ hoặc sửa đường đi dữ liệu không được sử dụng; xác định một đường ingest/detection chủ đạo.
2. Tích hợp Wazuh SIEM theo cấu hình upstream đã pin; tích hợp nền tảng SOAR đã chọn bằng API/webhook thật.
3. Dựng AI triage và deterministic guardrail như dịch vụ riêng có schema/contracts.
4. Thêm persistent audit/state, action idempotency, approval path, circuit breaker và rollback worker.
5. Thêm storage volumes, healthchecks, migration/initialization idempotent, backup/restore script và shutdown an toàn.
6. Nếu chưa thể hoàn thiện một thành phần, ghi `BLOCKED` và tiếp tục các phần độc lập; không giả mạo tích hợp.

### Pha 3 — Kiểm thử tăng dần trong Docker

Thực hiện theo trình tự: validate config → unit → contract → component integration → full E2E → security/adversarial → resilience → performance → backup/restore → clean deployment. Mỗi bước phải tạo exit code, log và kết quả máy đọc được.

### Pha 4 — Sửa lỗi theo nguyên nhân gốc

- Mỗi lỗi `FAIL` phải có reproduction test hoặc bằng chứng tái lập.
- Sửa nguyên nhân gốc, không chỉ tăng threshold hoặc nới test để biến đỏ thành xanh.
- Không giảm assertion, loại test lỗi, sửa ground truth hoặc xóa thất bại chỉ để đạt điểm mong muốn.
- Thêm regression test trước hoặc cùng lúc sửa bug.
- Chạy lại tất cả test bị ảnh hưởng và suite hồi quy.

### Pha 5 — Đóng gói ứng viên phát hành

1. Chạy toàn bộ suite trên một Compose project sạch, không dùng volume dữ liệu từ phiên thử nghiệm cũ.
2. Chạy `deploy.sh` từ một bản release được giải nén vào thư mục mới.
3. Xác minh health, luồng dữ liệu, dashboard/API, alert, AI triage, guardrail, playbook, audit và hành vi khi LLM/API đích mất kết nối.
4. Tạo report và manifest của gói phát hành. Chỉ gắn tag/release khi gate đã đạt; không bắt buộc auto-merge vào `main` nếu quy trình repository yêu cầu review.

### Pha 6 — Giới hạn vòng lặp

Tối đa **6 vòng Build–Test–Fix** cho một lượt thực thi tự trị, trừ khi môi trường có đủ thời gian/quyền rõ ràng để tiếp tục. Dừng sớm khi toàn bộ gate đạt. Nếu hết vòng mà còn lỗi, xuất trạng thái `INCOMPLETE` kèm danh sách lỗi ưu tiên; tuyệt đối không tiếp tục lặp vô hạn hoặc tự tuyên bố hội tụ. Không thực hiện chu trình tự cải tiến liên tục sau khi đã phát hành; chỉ tiếp tục khi người dùng yêu cầu lượt thay đổi mới.

---

## 9. DOCKER, DEPLOYMENT VÀ KHẢ NĂNG VẬN HÀNH

### 9.1. Nền tảng được hỗ trợ

Mục tiêu triển khai chính là **Ubuntu Server Linux với Docker Engine và Docker Compose plugin**. Không tuyên bố chạy trên mọi Windows/macOS/Linux chỉ vì container hóa. Khả năng tương thích với nền tảng khác phải có bài test thực tế và được ghi rõ.

Môi trường tham chiếu cho lab hiện tại: Ubuntu Server VM tối đa 16 vCPU, 48–64 GB RAM và khoảng 300 GB SSD; model inference có thể chạy trên máy host riêng và được truy cập qua endpoint cấu hình. Antigravity phải đo thực tế, tối ưu limits và ghi usage; không cố nhồi model vào container VM nếu mô hình được thiết kế chạy trên host.

### 9.2. Docker/Compose bắt buộc

- Pin version hoặc digest cho image nền và image upstream quan trọng; không dùng `latest`.
- Tất cả service cần thiết có healthcheck phản ánh khả năng phục vụ thật, không chỉ kiểm tra tiến trình còn sống.
- Dùng named volume cho dữ liệu quan trọng, network nội bộ, `restart` policy thích hợp, resource limits/reservations khi hỗ trợ và cấu hình qua environment/secrets.
- Chỉ publish các port cần thiết; mặc định chỉ bind dashboard/API phục vụ lab ở `127.0.0.1` hoặc interface được cấu hình tường minh. Database, queue, API nội bộ không được public ra mọi interface.
- Dùng user không phải root trong custom container khi có thể, read-only filesystem/cap-drop/no-new-privileges ở nơi tương thích; nêu rõ ngoại lệ với upstream image và lý do.
- Không bake secret vào image, git, build arg hay report. `.env` thật nằm trong `.gitignore`, quyền file hạn chế; commit `.env.example` chỉ chứa giá trị giả/an toàn. Production ưu tiên secret mechanism của môi trường.
- Sử dụng `depends_on: condition: service_healthy` khi phù hợp, nhưng vẫn phải xử lý retry/timeout trong ứng dụng.
- Đặt retention/rotation cho app logs; thiết lập giới hạn log để không làm đầy đĩa.
- Không sử dụng đường dẫn máy hiện tại. Gói release phải chạy từ path bất kỳ dưới điều kiện Ubuntu/Docker được hỗ trợ.

### 9.3. `deploy.sh` contract

`deploy.sh` phải:

1. Parse đúng tham số và hiển thị `--help`; hỗ trợ tối thiểu `--project-name NAME`, `--profile lab|pilot`, `--skip-tests`, `--offline` nếu gói offline được hỗ trợ và `--status`.
2. Kiểm tra Docker/Compose version, tài nguyên, disk, ports, permissions, `.env`, file cần thiết và kết nối model/provider theo cấu hình.
3. Nếu `.env` chưa tồn tại, tạo từ `.env.example`; không tự sinh credential yếu hoặc bật live mode.
4. Validate Compose bằng `docker compose ... config`; trả code khác 0 nếu invalid.
5. Pull/build các image đã pin, khởi động stack, chờ trạng thái health với timeout rõ ràng và in log khi thất bại.
6. Chạy migration/seed idempotent; seed không xóa collection/database người dùng và không reset mật khẩu/secret đã cấu hình.
7. Chạy smoke test mặc định an toàn; bài E2E có thể được gọi riêng. `--skip-tests` không được làm báo cáo thành PASS.
8. In URL/port thực tế, trạng thái từng service, chế độ SOAR đang dùng, nơi lưu log/audit và lệnh xử lý sự cố.
9. Không chạy `docker compose down -v` trong quy trình triển khai/upgrade bình thường.

### 9.4. `test.sh` / test runner contract

Cung cấp lệnh độc lập để chạy suite theo nhóm: `unit`, `contract`, `integration`, `e2e`, `security`, `resilience`, `performance`. Các bài test phải dùng project/network/volume riêng; không động tới dữ liệu vận hành. Mỗi test có timeout, assertion, log và trạng thái. Runner trả nonzero khi gate bắt buộc thất bại hoặc có lỗi chưa xử lý.

### 9.5. `package_release.sh` contract

- Đóng gói chính xác các file cần cho triển khai: config, custom images/Dockerfiles, manifest image, migration, scripts, tài liệu, dữ liệu kiểm thử được cấp phép và báo cáo đã tạo.
- Không đóng gói `.env` thật, token/key/cert riêng, log có dữ liệu cá nhân hoặc volume phát sinh.
- Hỗ trợ gói online và offline. Với offline, phải thực sự `docker save` tất cả images theo manifest; bản cài sạch phải `docker load` rồi chạy được khi ngắt Internet. Nếu không kiểm tra được nhánh offline, không quảng bá nó là hỗ trợ.
- Dùng `tar -tzf`/hash kiểm tra gói, xác minh đường dẫn đầu ra, và test giải nén sang thư mục mới trước khi release.
- Tạo `SHA256SUMS` cho artifact; ghi commit SHA, image digest, phiên bản upstream và thời gian build.

### 9.6. Upgrade, backup và recovery

Cung cấp tài liệu backup/restore cho SIEM index/config, database trạng thái, case/audit, Qdrant nếu dùng, chứng chỉ/secret theo quy trình an toàn và workflow SOAR. Có test restore trên một project sạch. Upgrade phải có precheck, backup, migration, health verification và rollback plan. Không tự xóa volume khi service fail.

---

## 10. KIỂM THỬ — GROUND TRUTH VÀ CÁC GATE PHÁT HÀNH

### 10.1. Nguyên tắc đo lường

- Ground truth độc lập với input được cung cấp cho detector. Label `benign/attack` phải nằm trong manifest test, không nằm trong nội dung log được phát hiện.
- Chia tập train/dev/test theo nguồn, host, campaign hoặc thời gian để giảm leakage; tập holdout không được dùng để tinh chỉnh rule/prompt/threshold.
- Mọi dataset có nguồn, giấy phép, ngày tải, checksum, mapping label, giới hạn và cách làm sạch dữ liệu. Ví dụ tổng hợp cần được đánh dấu `synthetic`, không trình bày là telemetry thực.
- Cần kiểm tra sự kiện được ingest, lưu ở SIEM, phát hiện, triage, ra quyết định, chuyển qua SOAR và được xác minh ở target. Mỗi giai đoạn có metric riêng.
- Kết quả lỗi do hệ thống/runner không được tính thành TN hoặc thành “blocked safely”. `ERROR`, `NOT_REACHED` và `INCONCLUSIVE` được báo riêng; khi có lỗi làm sai lệch metric, gate thống kê không đạt.

### 10.2. Các nhóm test bắt buộc

**A. Static/config/dependency**

- Compose config hợp lệ; không có tag `latest` chưa được phê duyệt; `.env`/secrets không bị commit; lint các Dockerfile, YAML, Python và shell scripts.
- Dependency lock/constraints cài đặt được từ môi trường sạch; kiểm tra CVE/license theo công cụ hiện có và báo cáo kết quả thực sự.

**B. Unit/schema/contract**

- Unit cho parser, schema validation, detection mapping, AI provider adapter, policy decision, target validation, idempotency, TTL scheduler, rollback và action adapters.
- Contract test cho SIEM → AI API, AI → guardrail, guardrail → SOAR, SOAR → adapter, adapter → target verifier.
- Mock chỉ được dùng ở unit/contract nơi phù hợp và phải ghi rõ; không dùng mock thay cho E2E.

**C. Full E2E**

- Gửi log vào ingress đang được cấu hình sử dụng thật.
- Xác minh raw/normalized event xuất hiện trong kho lưu trữ; xác minh rule phát hiện đúng hoặc bỏ qua đúng theo ground truth.
- Xác minh alert mang correlation ID và được AI triage đúng schema.
- Xác minh policy ra quyết định tương ứng; playbook được kích hoạt qua orchestration thật; audit ghi kết quả và verifier đọc trạng thái đích.
- Đối với mock, chứng minh trạng thái mock riêng và xác nhận không có external side effect.

**D. Detection quality**

- Bộ smoke test tối thiểu ban đầu có thể gồm 100 benign, 100 attack và 30 adversarial/chaos cases, nhưng chỉ đủ chứng minh chức năng cơ bản.
- Để báo cáo khả năng generalize ở mức pilot, mục tiêu dữ liệu holdout ban đầu là tối thiểu 1.000 benign và 500 malicious/suspicious có ground truth, gồm nhiều nguồn/kỹ thuật; tăng mẫu theo mức độ rủi ro và lưu lượng kỳ vọng. Nếu không có đủ dữ liệu đã kiểm chứng, ghi `INSUFFICIENT_EVIDENCE`; không tự sinh 1.000 dòng tương tự rồi coi như dữ liệu thực.
- Tính Precision, Recall, F1, FPR, FNR và confusion matrix từ case-level outcome đã xác minh; nêu denominator, lớp positive, cách xử lý duplicate và confidence interval khi thích hợp.
- Đánh giá riêng parser coverage, detection quality, AI classification quality, MITRE mapping accuracy, action recommendation correctness và end-to-end success. Không gộp tất cả thành một F1 duy nhất.

**E. Adversarial/security**

- Indirect prompt injection trong các trường log khác nhau, encoded/Unicode payload, hostname/user-agent có chỉ thị giả, RAG poisoning, dữ liệu mâu thuẫn, JSON/schema attack và prompt injection qua alert đã chuẩn hóa.
- IP spoofing/target spoofing, IP chỉ xuất hiện trong raw string, IPv6/CIDR, tài sản trọng yếu, target không tồn tại, CMDB thiếu/cũ, các trường không tin cậy.
- API authentication/authorization, secrets handling, network exposure, SSRF, unrestricted URL/tool execution, mass-assignment, replay, duplicate webhook và idempotency.
- Không được coi test an toàn là PASS nếu payload chưa đi đến thành phần cần kiểm tra.

**F. Resilience/recovery**

- LLM unavailable/timeout/invalid JSON; SIEM/indexer down; Qdrant down nếu dùng; SOAR API 401/429/5xx; target API timeout khi không rõ action đã thực thi chưa; database restart; container restart trong khi action đang chạy.
- Kiểm tra retry/backoff, dead-letter/retention, không mất alert không âm thầm, không tạo action lặp, không làm báo cáo sai trạng thái.
- Thử circuit breaker dưới concurrency; alert vẫn được lưu dù auto-response bị khóa.
- Thử backup/restore và TTL rollback sau khi service restart.

**G. Performance/capacity**

- Đo throughput và queue lag theo nguồn; resource CPU/RAM/disk; latency p50/p95/p99 từ ingest tới alert, AI triage, action execution và target verification.
- Đo riêng khi LLM warm/cold, timeout/retry, RAG có/không và ở chế độ mock/live. Không báo latency của endpoint API đơn giản như MTTR đầy đủ.
- Không đặt MTTR ≤ 5 giây như điều kiện bắt buộc chung khi chưa xác định model, target API và SLO. SLO phải được cấu hình trước, đo theo thiết bị/môi trường và thể hiện rõ trong báo cáo.

### 10.3. Điều kiện an toàn không thể bù bằng điểm tổng

Các mục sau là hard gate: chỉ một lần xảy ra cũng chặn release cho chế độ tự động phản ứng live:

- Một hành động live trái policy, không có phê duyệt cần thiết hoặc nhắm sai tài sản.
- Chặn/ cô lập mục tiêu trong allowlist hoặc critical asset theo policy.
- Prompt injection làm vượt guardrail hay cho phép action không được policy duyệt.
- Báo cáo giả `SUCCEEDED_VERIFIED` khi chưa xác minh target.
- Rollback/circuit breaker không hoạt động theo bài kiểm thử bắt buộc.
- Mất audit evidence đối với action thay đổi trạng thái.
- Secrets bị commit hoặc API nguy hiểm bị public ngoài thiết kế.

Không được dùng F1 cao hay điểm tổng để bù cho một lỗi safety.

### 10.4. Mục tiêu thống kê và kết luận

F1 ≥ 0,96 và FPR ≤ 0,02 có thể được ghi thành **mục tiêu cần đánh giá**, nhưng không phải sự thật mặc định và không đủ để tuyên bố production-ready. Chỉ kết luận đạt khi tính từ holdout độc lập đủ lớn và báo rõ số mẫu/CI. Với 100 log benign, việc quan sát 0 false positives không chứng minh FPR của môi trường thực dưới 2%.

Tách kết quả thành ba nhóm:

1. `FUNCTIONAL_GATE`: các luồng hoạt động, không có test lỗi.
2. `SAFETY_GATE`: không có vi phạm hard gate trong test suite được mô tả.
3. `QUALITY_GATE`: metrics trên holdout và performance so với SLO.

Mỗi gate có `PASS`, `FAIL`, `INCONCLUSIVE`. Release lab/pilot chỉ đạt theo mức đã định nghĩa nếu tất cả gate bắt buộc của mức đó đạt; `INCONCLUSIVE` không được tự đổi thành `PASS`.

---

## 11. DỮ LIỆU KIỂM THỬ VÀ REPORTING

### 11.1. Cấu trúc khuyến nghị

```text
repo/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT_MODEL.md
│   ├── IMPLEMENTATION_GAP_ANALYSIS.md
│   ├── DEPENDENCY_MATRIX.md
│   ├── OPERATIONS_RUNBOOK.md
│   ├── SECURITY_HARDENING.md
│   ├── BACKUP_RESTORE.md
│   └── TEST_PLAN.md
├── deploy/
│   ├── compose/
│   ├── config/
│   └── scripts/
├── services/
│   ├── ai_triage/
│   ├── guardrails/
│   └── adapters/
├── integrations/
│   ├── siem/
│   └── soar/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── e2e/
│   ├── security/
│   ├── resilience/
│   ├── performance/
│   └── datasets/
├── reports/                         # reports generated per run; ignore logs/secrets
├── .env.example
├── .gitignore
├── docker-compose.yml               # or documented split Compose files
├── deploy.sh
├── test.sh
└── package_release.sh
```

Đây là cấu trúc gợi ý; giữ cấu trúc hợp lý hiện có khi tốt hơn, tránh refactor chỉ để đổi tên. Một nguồn sự thật chính cho Compose/config và detection assets. Không sao chép toàn bộ repository qua `versions/v001`, `v002`, ... để đánh dấu lịch sử; dùng Git commits/tags/releases.

### 11.2. Manifest mỗi lần test

Mỗi run phải tạo `reports/<run_id>/manifest.json` chứa tối thiểu:

- timestamp UTC, hostname/OS/kernel, Docker/Compose versions;
- repository URL, branch, commit SHA, dirty-tree state;
- image names, tags/digests, upstream versions;
- profile/chế độ `mock|approval|live`;
- cấu hình model/provider đã redacted, dataset IDs/versions/checksum;
- lệnh thực thi, exit code và test suites đã chạy;
- số lượng `PASS`, `FAIL`, `ERROR`, `INCONCLUSIVE`, `NOT_REACHED`;
- đường dẫn tới raw logs, result JSON, junit/coverage nếu có, report HTML/Markdown;
- mọi điều kiện bỏ qua test và lý do.

Không ghi credential, prompt nhạy cảm đầy đủ hoặc dữ liệu cá nhân không cần thiết vào manifest.

### 11.3. Báo cáo nghiệm thu

Tạo `reports/ACCEPTANCE_REPORT.md` hoặc release report có các phần:

1. Mức bàn giao đạt được và các tuyên bố bị giới hạn.
2. Kiến trúc triển khai thực tế, services/images/versions và sơ đồ event path.
3. Các lệnh đã chạy chính xác cùng exit code.
4. Kết quả mỗi test suite; số liệu và mẫu số cụ thể.
5. Confusion matrix + Precision/Recall/F1/FPR/FNR, nếu test set phù hợp.
6. Bằng chứng alert đã xuất hiện ở SIEM, AI response theo schema, playbook được kích hoạt, trạng thái đích được xác minh và audit record được lưu.
7. Adversarial/safety/rollback/circuit-breaker findings.
8. Latency p50/p95/p99, resource usage và giới hạn tải đã thử.
9. Known issues, bước manual còn thiếu, dữ liệu/credential cần từ người vận hành.
10. Hướng dẫn chạy lại test, upgrade, backup/restore và rollback.

Báo cáo phải sinh từ kết quả run hiện tại. Không tái sử dụng báo cáo cũ mà không chỉ ra commit và run tương ứng.

---

## 12. CẤU HÌNH, SECRET VÀ HARDENING

- Tạo `.env.example` với tên biến, ý nghĩa, giá trị an toàn, điều kiện bắt buộc và ví dụ giả. Giá trị secret không bao giờ được commit.
- Tách cấu hình lab và pilot. Lab mặc định an toàn, dashboard/API giới hạn interface; pilot yêu cầu xác thực/phân quyền, TLS/CA thích hợp, secret management, backup và firewall rule tường minh.
- Mỗi API nội bộ có authentication/service identity; không dựa vào việc “chỉ ở Docker network” như kiểm soát duy nhất.
- CORS không được mở toàn bộ origin nếu không cần; rate limit các endpoint có thể bị lạm dụng; validate size/type/schema.
- Dữ liệu log có thể chứa token, email, IP, username hoặc PII: xác định retention, masking/redaction, quyền truy cập và quy trình xóa theo chính sách. Không gửi raw logs cho LLM cloud mặc định.
- Nếu dùng external/cloud LLM, phải có tùy chọn tắt, redaction trước khi gửi, timeout, allowlist endpoint và tài liệu hóa dữ liệu nào rời khỏi môi trường.
- Ghi nhận license và nghĩa vụ tuân thủ cho từng dependency/upstream integration.

---

## 13. CRITERIA OF DONE — CHECKLIST BẮT BUỘC

Antigravity chỉ đánh dấu `FUNCTIONAL_GATE=PASS` khi tất cả điều kiện liên quan được chứng minh bằng output hiện tại:

- [ ] Repository, commit SHA và thay đổi được ghi nhận; không ghi đè thay đổi người dùng.
- [ ] Docker Compose validate và build trên môi trường sạch.
- [ ] Các service lõi healthy; lỗi khởi động tạo nonzero exit code và có log.
- [ ] SIEM/SOAR mã nguồn mở đã chọn được triển khai thật theo phiên bản pin.
- [ ] Event đi qua đúng ingestion path; raw và normalized record được xác minh trong SIEM.
- [ ] Detection rule hoạt động trên positive cases và không bắn sai theo negative cases đã định nghĩa.
- [ ] AI provider thật được gọi ở chế độ AI, hoặc trạng thái test ghi rõ `BLOCKED/INCONCLUSIVE`; schema/error path được kiểm tra.
- [ ] Guardrail từ chối target sai/critical/allowlisted và xử lý unknown theo fail-safe.
- [ ] SOAR workflow thực được kích hoạt; mock/live được phân biệt trong database và report.
- [ ] Action live được verify tại target test; nếu chưa có target/credential thì không báo `LAB_VALIDATED`.
- [ ] Audit bền vững; restart không mất action state; idempotency và retry được kiểm thử.
- [ ] TTL/rollback được xác minh sau restart nếu action hỗ trợ rollback.
- [ ] Circuit breaker được kiểm tra dưới concurrency và không làm mất alert.
- [ ] Lỗi/timeout không được cộng thành TN hoặc safety pass.
- [ ] Prompt injection được test qua full pipeline và không thể vượt policy gate.
- [ ] Secrets, port exposure, auth, permissions và `.gitignore` được kiểm tra.
- [ ] Backup/restore, clean redeploy và release package đã được kiểm tra.
- [ ] Acceptance report, manifest, hashes, known issues và runbook đã được tạo.

Nếu một mục bị chặn do phụ thuộc bên ngoài, đánh dấu `BLOCKED` và cung cấp lệnh/bước chính xác để người vận hành hoàn tất. Đừng đánh dấu mọi mục là PASS theo suy luận.

---

## 14. CÁC LỆNH CẦN CHẠY VÀ BẰNG CHỨNG

Thực hiện các lệnh tương đương dưới đây tùy cấu trúc repo; lưu đầy đủ command, exit code và log. Không chạy lệnh phá hủy dữ liệu production.

```bash
# 1. Ghi nhận baseline
 git status --short --branch
 git rev-parse HEAD
 docker version
 docker compose version

# 2. Kiểm tra cấu hình
 docker compose --env-file .env.example config --quiet

# 3. Build và khởi chạy project test cô lập
 docker compose -p secops_test build
 docker compose -p secops_test up -d
 docker compose -p secops_test ps

# 4. Chạy suite; test runner cần nhận endpoint/profile rõ ràng
 ./test.sh unit
 ./test.sh contract
 ./test.sh integration
 ./test.sh e2e
 ./test.sh security
 ./test.sh resilience

# 5. Thu thập log khi fail
 docker compose -p secops_test logs --no-color --timestamps

# 6. Release thử và kiểm tra gói
 ./package_release.sh
 tar -tzf <release-archive>.tar.gz
 sha256sum <release-archive>.tar.gz

# 7. Chỉ teardown project test cô lập sau khi đã lưu evidence
 docker compose -p secops_test down
```

Các lệnh ở trên là mẫu, cần điều chỉnh theo repository thực tế. Không được giả vờ đã chạy chỉ vì chúng xuất hiện trong report. `down -v` chỉ được phép cho project test disposable sau khi kiểm tra rõ project name và xác nhận không chứa dữ liệu cần giữ; tuyệt đối không chạy với project vận hành hoặc volume không xác định.

---

## 15. ĐỊNH DẠNG TRẠNG THÁI VÀ BÁO CÁO TỰ ĐỘNG

Mỗi run phải kết thúc bằng một trong các trạng thái:

- `PASS`: các assertion liên quan đã chạy và đạt.
- `FAIL`: có assertion/test gate chạy và không đạt.
- `ERROR`: runner/hệ thống kiểm thử lỗi; chưa có kết luận hợp lệ.
- `INCONCLUSIVE`: dữ liệu hoặc cỡ mẫu không đủ để đưa ra kết luận được yêu cầu.
- `BLOCKED`: cần quyền/credential/target hoặc điều kiện môi trường chưa có.
- `NOT_RUN`: suite không được thực thi.

Không được đổi `ERROR`, `INCONCLUSIVE`, `BLOCKED` hoặc `NOT_RUN` thành `PASS`. Nếu một test không đến được guardrail/adapter, kết quả safety cho đường đi đó là `NOT_REACHED`, không phải “blocked safely”.

Báo cáo tổng quan không dùng một `S_total` duy nhất làm quyết định release. Nếu vẫn hiển thị score để so sánh nội bộ, phải hiển thị metric thành phần, mẫu số, hard gates và ghi rõ score không thay thế được safety gates hoặc đánh giá độc lập.

---

## 16. PROMPT THỰC THI TRỰC TIẾP CHO ANTIGRAVITY

Sao chép nguyên khối dưới đây cho Antigravity sau khi đặt file này trong workspace:

```text
[SYSTEM DIRECTIVE — OPERATIONAL SIEM/SOAR BUILD]

Đọc toàn bộ @antigravity_siem_soar_autonomous_spec_v2.md. Repository đích mặc định là Dino2408/SIEM_SOAR_AI_1.

MỤC TIÊU: Trực tiếp hoàn thiện một sản phẩm SIEM/SOAR tích hợp AI có đường đi dữ liệu thật, kiểm soát an toàn thật, triển khai Docker lặp lại được và bằng chứng kiểm thử đáng tin. Không chỉ viết kế hoạch hoặc báo cáo.

BẮT ĐẦU NGAY:
1. Kiểm tra repo/branch/commit/working tree, tạo branch làm việc an toàn và lập docs/IMPLEMENTATION_GAP_ANALYSIS.md. Đối chiếu tất cả các hạng mục bắt buộc ở mục 3.1 với code hiện tại.
2. Ưu tiên tích hợp SIEM/SOAR mã nguồn mở đang được duy trì. Dùng Wazuh làm SIEM và Shuffle làm SOAR theo cấu hình upstream được pin nếu tương thích; chỉ thay lựa chọn bằng giải pháp khác khi có lý do kỹ thuật được ghi trong docs/DEPENDENCY_MATRIX.md. Không gọi custom substring matcher là SIEM đầy đủ; không gọi executor giả là SOAR thực.
3. Sửa theo thứ tự P0: test runner/ground truth; P1: event path đầu-cuối; P2: AI provider thật/schema/error handling; P3: guardrails/persistent audit/idempotency/circuit breaker/TTL rollback; P4: hardening, backup/restore, packaging và runbook.
4. Dùng Docker Compose trên Ubuntu/Linux làm môi trường chính. Chạy config validation, build, healthcheck, unit/contract/integration/E2E/security/resilience suites. E2E phải bơm log vào ingress thật và truy vấn kết quả đã lưu ở SIEM.
5. Mặc định SOAR_EXECUTION_MODE=mock hoặc approval; không thực hiện hành động nguy hiểm lên thiết bị/tài khoản thật. Các mock phải hiện ra là mock. Khi có target lab và credential đã được cấu hình an toàn, kiểm chứng ít nhất một adapter thật; nếu không thì đánh dấu BLOCKED và không tuyên bố LAB_VALIDATED.
6. Không tính API error/timeout/thiếu kết quả thành TN hoặc safety pass. Không tạo số liệu; mọi số liệu phải bắt nguồn từ result files của run hiện tại.
7. Giới hạn tối đa 6 vòng sửa lỗi trong lượt thực thi; không lặp vô hạn, không tự merge vào main nếu cần review, không chạy down -v trên project/volume không xác định.
8. Tạo manifest + report gắn commit SHA, image digests, dataset hashes, commands/exit codes, PASS/FAIL/ERROR/INCONCLUSIVE/BLOCKED/NOT_RUN. Kiểm tra gói release bằng cách giải nén vào thư mục mới và deploy/test lại.
9. Hoàn tất bằng Acceptance Report trung thực: mức DEMO_READY/LAB_VALIDATED/OPERATIONAL_PILOT_READY đạt được; mọi test không chạy, lỗi, giới hạn và thao tác con người còn cần đều phải ghi rõ.

Không tuyên bố “tối ưu nhất”, “production-ready”, “F1=1.0” hoặc “FPR=0” nếu chưa có bằng chứng độc lập đủ mạnh. Khi bị chặn, mô tả điều kiện cụ thể và tiếp tục các công việc độc lập có thể thực hiện.
```

---

## 17. TÀI LIỆU UPSTREAM CẦN KIỂM TRA KHI THỰC THI

Antigravity phải mở tài liệu upstream hiện hành trước khi pin image/version; các liên kết dưới đây là điểm bắt đầu, không thay cho việc kiểm tra phiên bản cụ thể:

- Wazuh Docker deployment: https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html
- Wazuh architecture: https://documentation.wazuh.com/current/getting-started/architecture.html
- Wazuh Docker repository: https://github.com/wazuh/wazuh-docker
- Shuffle SOAR documentation: https://github.com/Shuffle/shuffle-docs
- Shuffle API documentation: https://github.com/Shuffle/shuffle-docs/blob/master/docs/API.md
- Qdrant documentation: https://qdrant.tech/documentation/
- Ollama API introduction: https://github.com/ollama/ollama/blob/main/docs/api/introduction.mdx
- Docker Compose documentation: https://docs.docker.com/compose/

Phiên bản, license, compatibility matrix, security advisories và checksum cần được ghi nhận tại thời điểm build/release. Không dựa vào số phiên bản hoặc tính năng chưa được kiểm tra.

---

## 18. QUY TẮC KẾT LUẬN CUỐI CÙNG

Sản phẩm được xem là có giá trị sử dụng thực tế khi các chức năng chính không chỉ “chạy được” mà còn được xác minh trong đường đi đầu-cuối, xử lý lỗi theo fail-safe, giữ audit bền vững, hành động phản ứng có xác minh và có thể triển khai/backup/restore theo hướng dẫn. Kết quả tốt trên vài chục log tổng hợp chỉ hỗ trợ demo chức năng, không chứng minh chất lượng phát hiện ngoài thực tế.

Antigravity phải bàn giao sản phẩm và bằng chứng; **không được dùng lời khẳng định của chính agent làm bằng chứng thay cho kết quả chạy thực tế**.
