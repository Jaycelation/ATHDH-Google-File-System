# Mối đe dọa

## Length Extension Attack

### Mô tả mối đe doạ

- **Length Extension Attack** (tấn công mở rộng độ dài) là một kỹ thuật tấn công khai thác tính chất tuyến tính hoặc cấu trúc nội tại của một số thuật toán kiểm tra toàn vẹn, cho phép kẻ tấn công nối thêm dữ liệu độc hại vào một chuỗi ban đầu mà vẫn duy trì được mã kiểm tra hợp lệ (checksum).
- Trong trường hợp sử dụng **CRC32** — một thuật toán kiểm tra lỗi dựa trên phép chia đa thức — kẻ tấn công có thể lợi dụng tính chất toán học của thuật toán này để tính toán trước giá trị CRC cho phần dữ liệu nối thêm mà không cần biết toàn bộ nội dung ban đầu. Điều này là do CRC32 có tính **tuyến tính**, cho phép tính CRC của chuỗi nối tiếp `M || X` từ CRC của `M`, độ dài `|M|`, và dữ liệu nối thêm `X` thông qua hàm kết hợp dạng:
    
    ```arduino
    CRC(M || X) = F(CRC(M), CRC(X), |M|)
    ```
    
    Trong đó:
    
    - `F(...)` là hàm tuyến tính của CRC32, có thể được tính toán từ giá trị CRC32 của phần gốc (`CRC(M)`), giá trị CRC32 của phần nối thêm (`CRC(X)`), và độ dài của dữ liệu gốc (`len(M)`)
    - `CRC(M)` là giá trị CRC của dữ liệu gốc
    - `len(M)` là độ dài của dữ liệu gốc
- Kẻ tấn công có thể lợi dụng đặc điểm này để thêm dữ liệu độc hại vào cuối một chuỗi mà vẫn giữ nguyên giá trị CRC cuối cùng, đánh lừa hệ thống rằng nội dung chưa hề bị thay đổi.



### Cách thức mối đe dọa ảnh hưởng đến giải pháp đã chọn

- **Ảnh hưởng đến tính toàn vẹn dữ liệu**: GFS không phát hiện được dữ liệu giả mạo khi checksum vẫn hợp lệ.
    - Ví dụ minh họa:
        - Giả sử một tệp chứa chuỗi `"payment=100"` có CRC32 là `0x853bae56`
        - Hệ thống sử dụng **CRC32** để tính toán mã kiểm tra toàn vẹn cho nội dung này và lưu trữ giá trị CRC32 tương ứng là:
        
        ```arduino
        CRC32("payment=100") = 0x853bae56
        ```
        
        → Kẻ tấn công, nhờ truy cập vào metadata hệ thống (hoặc các bản sao chunk dữ liệu), có thể biết được:
        
        - Giá trị CRC32 của chuỗi gốc (`0x853bae56`)
        - Độ dài của dữ liệu gốc (`11 byte` trong trường hợp này)
        
        → Lợi dụng tính **tuyến tính** của CRC32, kẻ tấn công tiến hành thực hiện tấn công mở rộng độ dài như sau:
        
        1. Thêm một đoạn padding hợp lệ (ví dụ một hoặc nhiều byte `\x00`) để căn chỉnh dữ liệu và chuẩn bị cho thao tác nối.
        2. Chèn dữ liệu độc hại như:
        
        ```arduino
        , bonus=900
        ```
        
        3. Tính toán lại giá trị CRC32 cho toàn bộ chuỗi **`payment=100 + padding + , bonus=900`** sao cho kết quả cuối cùng khớp với giá trị mong muốn (hoặc giả lập một CRC hợp lệ mà hệ thống không kiểm soát theo chiều ngược lại). [Source](/Demo/CRC32_LEA.py)
        
        ![image.png](/Demo/images/image%2015.png)

        
        
- **Gây lan truyền dữ liệu sai lệch:** Dữ liệu bị thao túng trên một chunkserver được sao chép sang các bản sao khác, làm toàn bộ hệ thống lưu trữ phiên bản sai.
- **Làm hỏng quy trình khôi phục**: Dữ liệu giả mạo được coi là hợp lệ, gây khó khăn cho việc khôi phục hoặc kiểm tra tính nhất quán giữa các node.



## **Checksum Spoofing**



### Mô tả mối đe doạ

- **Checksum Spoofing** xảy ra khi một kẻ tấn công cố gắng tạo ra hoặc thay đổi một checksum sao cho nó khớp với nội dung dữ liệu đã bị thay đổi. Mục tiêu của tấn công này là thay đổi nội dung dữ liệu mà không làm thay đổi giá trị checksum đi kèm, khiến hệ thống không nhận ra sự thay đổi.
- Nguyên lý hoạt động: CRC32 (Cyclic Redundancy Check 32-bit) là một hàm băm đơn giản dùng để phát hiện lỗi trong dữ liệu, nhưng nó không phải là hàm băm mật mã (cryptographic hash). Do đó, nó có thể bị "đảo ngược" hoặc thao túng thông qua việc tính toán một giá trị **Δ** (delta) sao cho khi áp dụng vào dữ liệu gốc, checksum của dữ liệu mới vẫn giữ nguyên hoặc đạt được giá trị mong muốn. Cụ thể:
    - Với dữ liệu gốc **M** và checksum **C**, kẻ tấn công muốn tạo dữ liệu mới **M'** sao cho **CRC(M') = C** (hoặc một giá trị cụ thể khác).
    - Bằng cách giải phương trình **CRC(M ⊕ Δ) = C'**, kẻ tấn công tìm được **Δ**, sau đó áp dụng nó để biến đổi **M** thành **M'**.

### Cách thức mối đe dọa ảnh hưởng đến giải pháp đã chọn

- **Ảnh hưởng đến tính toàn vẹn dữ liệu**: GFS dựa vào CRC32 để kiểm tra tính toàn vẹn của các chunk dữ liệu (thường là 64MB). Khi kẻ tấn công tạo ra dữ liệu giả mạo có cùng giá trị CRC32 với dữ liệu gốc, hệ thống không thể phát hiện sự thay đổi.
    - Ví dụ minh họa:
        - Giả sử một tệp chứa chuỗi `"payment=100"` có CRC32 là `0x853bae56`.
        - GFS sử dụng **CRC32** để tính toán mã kiểm tra toàn vẹn cho nội dung này và lưu trữ giá trị CRC32 tương ứng:
        
        ```arduino
        CRC32("payment=100") = 0x853bae56
        ```
        
        → Kẻ tấn công, nhờ truy cập vào metadata hoặc chunk dữ liệu, biết được:
        
        - Giá trị CRC32 gốc (`0x853bae56`).
        - Độ dài dữ liệu (11 byte).
        
        → Lợi dụng tính **tuyến tính** của CRC32, kẻ tấn công thực hiện thao túng như sau:
        
        1. Chọn dữ liệu mới mong muốn, ví dụ: `"payment=999"`.
        2. Tính toán **Δ** (delta) sao cho:
        
        ```arduino
        CRC32("payment=100" ⊕ Δ) = 0x853bae56
        ```
        
        3. Áp dụng **Δ** để tạo dữ liệu giả mạo `"payment=999"` với CRC32 khớp giá trị gốc. [Source](/Demo/CRC32_CS.py)
        
        ![image.png](/Demo/images/image%2016.png)
        
- **Gây lan truyền dữ liệu sai lệch:** Dữ liệu bị thao túng trên một chunkserver được sao chép sang các bản sao khác, làm toàn bộ hệ thống lưu trữ phiên bản sai.
- **Làm hỏng quy trình khôi phục**: Dữ liệu giả mạo được coi là hợp lệ, gây khó khăn cho việc khôi phục hoặc kiểm tra tính nhất quán giữa các node.



## **SQL Injection**



### Mô tả mối đe doạ

- Lỗ hổng SQL Injection (SQLi) nhắm vào các hệ thống file phân tán như GFS là một dạng tấn công khai thác lỗ hổng trong cách hệ thống xử lý đầu vào người dùng, đặc biệt khi các truy vấn SQL không được bảo vệ đúng cách. Trong trường hợp này, kẻ tấn công chèn mã SQL độc hại vào một tham số (ví dụ: filename) để thao túng cơ sở dữ liệu, cụ thể là thay đổi giá trị checksum của một tệp mà không cần sửa đổi nội dung thực tế của tệp đó.
- Điều kiện: Lỗ hổng xảy ra trong hệ thống phân tán nếu các yêu cầu đến cơ sở dữ liệu (CSDL) không được xử lý đúng cách:
    - **Thiếu kiểm tra và xác thực đầu vào:** Nếu hệ thống không kiểm tra và xác thực đầu vào của người dùng đúng cách, kẻ tấn công có thể gửi các tham số chứa mã SQL độc hại.
    - **Cấu hình bảo mật không đầy đủ:** Các máy chủ trong hệ thống phân tán GFS được cấu hình bảo mật không nhất quán, chẳng hạn như cấp quyền sai hoặc không kiểm tra quyền truy cập đến cơ sở dữ liệu của người dùng, tạo ra cơ hội cho kẻ tấn công khai thác lỗ hổng SQL injection.
- Cơ chế hoạt động
    - Khi hệ thống thực thi một câu lệnh SQL không được kiểm soát (ví dụ: nối chuỗi trực tiếp từ đầu vào người dùng), kẻ tấn công có thể chèn thêm các lệnh SQL như `UPDATE` để sửa đổi dữ liệu trong bảng `files`.
    - Ví dụ: Với đầu vào `filename=legit.txt'; UPDATE files SET checksum='0x853bae56' WHERE id=1 --`, hệ thống sẽ:
        1. Thực thi phần hợp lệ của truy vấn ban đầu (liên quan đến legit.txt).
        2. Tiếp tục thực thi lệnh `UPDATE` để thay đổi checksum của tệp có id=1 thành giá trị giả mạo (`0x853bae56`).
        3. Dấu `--` comment bỏ phần còn lại của truy vấn gốc, tránh lỗi cú pháp.



### Cách thức mối đe dọa ảnh hưởng đến giải pháp đã chọn

- Ảnh hưởng trực tiếp
    - **Thay đổi checksum trong metadata**: Nếu kẻ tấn công sử dụng SQLi để thay đổi giá trị CRC32 trong cơ sở dữ liệu (ví dụ: từ giá trị hợp lệ của legit.txt thành `CRC32('malware'))`, hệ thống sẽ sử dụng giá trị giả mạo này để kiểm tra tính toàn vẹn. Khi đó:
        - Một tệp độc hại (có nội dung khác) nhưng khớp với checksum giả mạo sẽ được coi là hợp lệ.
        - Ngược lại, tệp gốc hợp lệ có thể bị từ chối nếu nội dung không khớp với checksum giả.
    - **Bypass cơ chế kiểm tra toàn vẹn**: Trong GFS, CRC32 là lớp bảo vệ chính để phát hiện hỏng hóc dữ liệu hoặc tấn công. SQLi cho phép kẻ tấn công vô hiệu hóa lớp bảo vệ này mà không cần truy cập trực tiếp vào tệp hoặc chunk server.
- **Tác động đến GFS**
    - **Mất tính toàn vẹn dữ liệu**: GFS phụ thuộc vào CRC32 để đảm bảo dữ liệu không bị thay đổi trong quá trình lưu trữ hoặc truyền tải. Khi checksum bị thao túng, hệ thống không còn khả năng phát hiện sự khác biệt giữa dữ liệu gốc và dữ liệu bị sửa đổi.
    - **Ảnh hưởng đến tính sẵn sàng**: Nếu checksum giả mạo không khớp với nội dung thực tế, GFS có thể đánh dấu các chunk hợp lệ là hỏng và kích hoạt cơ chế sửa chữa không cần thiết, gây lãng phí tài nguyên hoặc thậm chí làm gián đoạn dịch vụ.
    - **Tấn công leo thang đặc quyền**: Kẻ tấn công có thể dùng SQLi để thay đổi checksum của nhiều tệp quan trọng (ví dụ: tệp hệ thống hoặc dữ liệu nhạy cảm), từ đó mở đường cho các cuộc tấn công khác như phân phối mã độc hoặc làm hỏng toàn bộ cụm dữ liệu.



# Cách thức giải pháp xử lý/giải quyết mối đe doạ

## Mã hóa song song

### Mô tả

- **Ý tưởng**: CRC32 là một hàm băm không có tính chất mã hóa (non-cryptographic hash), dễ bị tấn công nếu kẻ tấn công biết giá trị băm và độ dài dữ liệu gốc. Để khắc phục, bổ sung một cơ chế kiểm tra độc lập song song với CRC32 mà không thay đổi thuật toán chính.
- **Mục tiêu**: Tăng cường bảo mật bằng cách thêm một lớp mã hóa ngoài CRC32 để kẻ tấn công không thể dễ dàng thao túng dữ liệu mà vẫn giữ CRC32 hợp lệ.
- **Cách triển khai**
    - Sử dụng một hàm băm mã hóa (cryptographic hash) như SHA-256 song song với CRC32.
    - Lưu giá trị SHA-256 trong metadata cùng với CRC32.
    - Khi kiểm tra tính toàn vẹn, so sánh cả hai giá trị (CRC32 và SHA-256).

### Code

- [Source](/Demo/Solution.py)
    
    ```python
    import zlib
    import hashlib
    
    def calculate_crc32(data):
        return zlib.crc32(data) & 0xFFFFFFFF
    
    def calculate_sha256(data):
        return hashlib.sha256(data).hexdigest()
    
    def secure_data_integrity(original_data):
        crc32_value = calculate_crc32(original_data)
        sha256_value = calculate_sha256(original_data)
        print(f"Dữ liệu gốc: {original_data.decode()}")
        print(f"CRC32: {hex(crc32_value)}")
        print(f"SHA256: {sha256_value}")
        return crc32_value, sha256_value
    
    def verify_integrity(data, expected_crc32, expected_sha256):
        new_crc32 = calculate_crc32(data)
        new_sha256 = calculate_sha256(data)
        return new_crc32 == expected_crc32 and new_sha256 == expected_sha256
    
    original_data = b"payment=100"
    crc32_orig, sha256_orig = secure_data_integrity(original_data)
    
    extended_data = b"payment=100\x00, bonus=900"
    is_valid = verify_integrity(extended_data, crc32_orig, sha256_orig)
    print(f"Dữ liệu sau tấn công: {extended_data.decode()}")
    print(f"Kết quả kiểm tra: {is_valid}")
    ```
    
    ![image.png](/Demo/images/image%2017.png)

## Phát hiện bất thường dựa trên ngữ nghĩa

### Mô tả

- **Ý tưởng**: CRC32 chỉ kiểm tra tính toàn vẹn bit, không kiểm tra ý nghĩa dữ liệu. Thêm một lớp kiểm tra ngữ nghĩa để phát hiện dữ liệu giả mạo.
- **Mục tiêu**: Xây dựng một bộ quy tắc đơn giản để kiểm tra định dạng dữ liệu (data format validation). Ví dụ:
    - Chuỗi hợp lệ phải có dạng `key=value` và không chứa ký tự ngoài dự kiến (`, % \x00,` …). → Sử dụng kết hợp blacklist (Cấm các từ không hợp lệ) và whitelist (Chỉ cho phép các từ hợp lệ)
    - Nếu dữ liệu chứa các trường không mong muốn, hệ thống đánh dấu là bất thường, ngay cả khi CRC32 hợp lệ.
- Cách triển khai
    - Xác thực tất cả đầu vào: Kiểm tra định dạng, độ dài, phạm vi và loại dữ liệu
    - Tạo 2 danh sách bao gồm blacklist và whitelist


### Code

- [Source](/Demo/REgex.py)
    
    ```python
    import re
    
    VALID_PATTERN = r"^[a-zA-Z]{1,20}=[0-9]{1,10}$"
    
    BLACKLIST_PATTERN = (
        r"[<>'\";,%/.]"
        r"|\s+"
        r"|--"
        r"|\b(?:OR|AND|UNION|SELECT|DROP|INSERT|UPDATE|DELETE|EXEC|EXECUTE|CREATE|ALTER|TRUNCATE|SLEEP|BENCHMARK|LIKE|WHERE)\b"
        r"|!=|=--|#|/\*|\*/"
        r"|%3C|%3E|%22|%27|%2F" 
    )
    ```

---

## Demo

- Khởi động các Chunk Server
    - Các **ChunkServer** được khởi chạy lần lượt trên các cổng 50052 → 50056
    - Mỗi Server có một thư mục riêng trên hệ thống tệp, ví dụ (root_chunkserver/50052)
- Tạo file
    - Khi tạo file mới (/file), Master Server sẽ tạo ra **một chunk mới** trên 3 ChunkServer khác nhau (55, 56, 52)
    - Mỗi server tạo ra một file chunk với cùng **UUID (mã định danh duy nhất)**: `4f2816ba-11ff-11f0-bd88-00155dab7b0a`
        
        → Đảm bảo một chunk dữ liệu được **sao chép nhiều lần (replica)** trên nhiều node để đảm bảo tính sẵn sàng và an toàn dữ liệu.
        
    
    ![image.png](/Demo/images/image.png)
    
    ![image.png](/Demo/images/image%201.png)
    
- Ghi file
    - Client gửi dữ liệu đến Chunkserver, dữ liệu được chia thành các block có kích thước 64KB
    - Server sẽ thêm dữ liệu lần lượt vào các chunk đó trên từng ChunkServer replica
    - Mỗi chunk có giới hạn 4 byte dung lượng khả dụng mỗi lần append, nếu đầy Master sẽ tạo ra các chunk với ID mới
    - Checksum được lưu vào Metadata: lưu cùng với vị trí block tương ứng và ghi vào operation log để đảm bảo tính bền vững. Dữ liệu được ghi vào chunk file và checksum lưu trong metadata có phần header của chunk
    
    ### Chi tiết các chunk:
    
    ### Chunk 1: `4f2816ba-11ff-11f0-bd88-00155dab7b0a`
    
    - Append dữ liệu `"Hell"` (4 bytes) → checksum: `0xbcb4afdd`
    - Thao tác này được thực hiện **trên cả 3 ChunkServer** (50055, 50056, 50052)
    
    ![image.png](/Demo/images/image%202.png)
    
    - Tạo chunk mới với id `6fdf90d1-11ff-11f0-9ef9-00155dab7b0a` trên các chunkserver (50052, 50053, 50054)
    
    ![image.png](/Demo/images/image%203.png)
    
    ### Chunk 2: `6fdf90d1-11ff-11f0-9ef9-00155dab7b0a`
    
    - Append dữ liệu `"o wo"` (4 bytes) → checksum: `0xc73fed51`
    - Cũng được thực hiện **trên cả 3 ChunkServer** → checksum đồng nhất.
    
    ![image.png](/Demo/images/image%204.png)
    
    - Tạo chunk mới với id `6fe28868-11ff-11f0-b2e2-00155dab7b0a` trên các chunkserver (50054, 50055, 50056)
    
    ![image.png](/Demo/images/image%205.png)
    
    ### Chunk 3: `6fe28868-11ff-11f0-b2e2-00155dab7b0a`
    
    - Append dữ liệu `"rld"` (3 bytes) → checksum: `0x2ba3e4c6`
    - Được ghi thành công trên cả 3 server dù còn dư 1 byte.
    
    ![image.png](/Demo/images/image%206.png)
    
    - Response từ Master tương ứng bao gồm tên chunk được tiếp nhận dữ liệu, id chunk, trạng thái trả về
    
    ![image.png](/Demo/images/image%207.png)
    
    - Metadata
    
    ![image.png](/Demo/images/image%208.png)
    

- Liệt kê file
    
    ![image.png](/Demo/images/image%209.png)
    

- Đọc file
    - Client gửi yêu cầu chứa chunk handle và offset để đọc dữ liệu (đọc file /file 
    bắt đầu từ **offset 0**, và đọc **20 bytes)**
    
    ![image.png](/Demo/images/image%2010.png)
    
    → Phản hồi từ chunkserver: 
    
    ```bash
    Response from master: 
    4f2816ba-11ff-11f0-bd88-00155dab7b0a*50055*0*4 |
    6fdf90d1-11ff-11f0-9ef9-00155dab7b0a*50052*0*4 |
    6fe28868-11ff-11f0-b2e2-00155dab7b0a*50054*0*4
    ```
    
    **Giải nghĩa từng phần:**
    
    - Dữ liệu được chia thành **chunk**, mỗi chunk khoảng 4 bytes.
    - Mỗi dòng có format:
        
        `chunk_id*chunkserver_port*offset*length`
        
    
    **Ví dụ:**
    
    - Chunk ID: `4f2816ba-11ff-11f0-bd88-00155dab7b0a*50055*0*4`
    - Nằm trên ChunkServer cổng **50055**
    - Đọc từ offset 0, dài **4 bytes**
    
    → Master nói rằng để đọc 20 bytes, client nên:
    
    - Đọc **4 bytes đầu tiên từ chunk 1 tại CS 50055**
    - Đọc **4 bytes tiếp theo từ chunk 2 tại CS 50052**
    - Đọc **3 bytes từ chunk 3 tại CS 50054**
        
        Tổng cộng là **11 bytes**, vì hiện tại file chỉ có `"Hello world"` (11 ký tự), nên không cần đọc đủ 20 bytes.
        
        ![image.png](/Demo/images/image%2011.png)
        
    - Server dựa vào checksum được lưu trên root_chunkserver (Stored checksum) và checksum tính toán hiện tại (Current checksum). Nếu 2 checksum khớp, dữ liệu sẽ được đọc → Đảm bảo tính toàn vẹn
- Sửa đổi metadata làm mất tính toàn vẹn
    - Sửa đổi file metadata trên root_chunkserver
        
        ![image.png](/Demo/images/image%2012.png)
        
    - Đọc file một lần nữa để kiểm tra → Báo lỗi vì không khớp checksum
        
        ![image.png](/Demo/images/image%2013.png)
        
        ![image.png](/Demo/images/image%2014.png)

