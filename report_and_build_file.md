# REPORT VỀ TRIỂN  KHAI RC4 ALGORITHM BẰNG ASM x86 


## Yêu cầu :
- Ngôn ngữ: Assembly x86 (32-bit)
- Thư viện: Chỉ sử dụng WinAPI (GetStdHandle, WriteConsoleA, ReadConsoleA, ExitProcess)
- Đầu vào: Key và plaintext nhập qua bàn phím
- Đầu ra: Chuỗi hex của ciphertext 
- Tổ chức: Mã được chia thành các hàm, mỗi dòng có comment giải thích rõ ràng

---

## Cách biên dịch và chạy

- **Môi trường**: Windows, sử dụng NASM và linker (GoLink)

 Cài nasm và golink

Bật cmd hoặc window powershell

### Biên dịch:

```bash
nasm -f win32 rc4.asm -o rc4.obj
golink /console /entry _start rc4.obj kernel32.dll
```
## Cấu trúc mã nguồn

Mã được tổ chức thành các phần chính, mỗi phần đảm nhiệm một chức năng cụ thể:
### 1. Biến và bộ nhớ

### `.data`:

- `hStdIn`, `hStdOut`: handle console
- Các chuỗi thông báo: `keyMsg`, `plaintextMsg`, `resultMsg`, `newline`
- Độ dài chuỗi: `keyMsgLen`, v.v.

### `.bss`:

- `s[256]`: mảng trạng thái RC4
- `key[256]`, `text[1024]`: buffer input/output
- `hex[2048]`: chuỗi hex kết quả
- `bytesRead`, `bytesWritten`: lưu số byte đọc/ghi
- `keyLen`, `textLen`: độ dài key và plaintext
- `i`, `j`, `temp`: biến tạm
---
### 2. Khởi tạo và nhập/xuất dữ liệu (WinAPI)

#### a. Hàm `_start`

- **Mục đích**: Khởi tạo handle console và gọi các hàm chính
- **Thanh ghi sử dụng**:
  - `eax`: lưu handle trả về từ `GetStdHandle`

**Các bước:**

1. Lấy handle đầu vào và đầu ra qua `GetStdHandle`.
2. Gọi lần lượt: `get_key`, `get_plaintext`, `rc4_init`, `rc4_encrypt`, `display_hex_result`.
3. Gọi `ExitProcess(0)` để thoát chương trình.

**Lưu ý**: Tham số WinAPI đẩy lên stack theo thứ tự ngược 

#### b. Hàm `get_key`

- Nhập key từ bàn phím và lưu vào buffer `key`

**Thanh ghi sử dụng**: `eax`, `ebx`, `ecx`

**Các bước:**

1. Hiển thị thông báo "Nhap key: "
2. Đọc key (tối đa 255 byte).
3. Trừ 2 byte (CR, LF), lưu `keyLen`
4. Thêm null terminator

#### c. Hàm `get_plaintext`

- Nhập plaintext từ bàn phím và lưu vào buffer `text`

**Thanh ghi sử dụng**: `eax`, `ebx`, `ecx`

**Các bước**: Tương tự `get_key`, nhưng áp dụng cho plaintext

---

### 3. KSA

#### Hàm `rc4_init`

- **Mục đích**: Khởi tạo mảng trạng thái `S[256]` và xáo trộn theo key.

**Thanh ghi sử dụng**: `eax`, `ebx`, `ecx`, `edx`, `cl`, `ch`

**Các bước:**

1. Khởi tạo `S[i] = i` (0 → 255)
2. Với từng `i`:
   - Tính `j = (j + S[i] + key[i % keyLen]) % 256`
   - Hoán đổi `S[i]` và `S[j]`
3. Đặt `i`, `j` về 0 cho PRGA

**Lưu ý**: Dùng `div` để lấy `i % keyLen`

---

### 4. PRGA

#### Hàm `rc4_encrypt`

- **Mục đích**: Tạo keystream và mã hóa plaintext thành ciphertext bằng XOR

**Thanh ghi sử dụng**: `esi`, `edi`, `ecx`, `eax`, `ebx`, `edx`, `bl`, `bh`

**Các bước:**

1. Vòng lặp với `textLen` lần:
   - `i = (i + 1) % 256`
   - `j = (j + S[i]) % 256`
   - Hoán đổi `S[i]` và `S[j]`
   - `K = S[(S[i] + S[j]) % 256]`
   - `ciphertext[n] = plaintext[n] ^ K`

**Lưu ý**: Mã hóa tại chỗ

---

### 5. Chuyển đổi và hiển thị kết quả hex

#### Hàm `display_hex_result`

- **Mục đích**: Chuyển ciphertext thành chuỗi hex và in ra màn hình.

**Thanh ghi sử dụng**: `esi`, `edi`, `ecx`, `eax`, `ebx`

**Các bước:**

1. Hiển thị thông báo "Ma hoa (HEX): "
2. Với mỗi byte:
   - Tách nibble cao và thấp.
   - Gọi `nibble_to_hex` để chuyển sang ký tự
3. In chuỗi hex bằng `WriteConsoleA`

#### Hàm `nibble_to_hex`

- Chuyển nibble (0–15) thành ký tự `'0'`–`'9'` hoặc `'A'`–`'F'`

**Các bước:**

- Nếu `al <= 9`: cộng `'0'`
- Ngược lại: cộng `'A' - 10`

---
## ***<p style="color:red;">by hieesu19</p>***




