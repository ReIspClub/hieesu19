# **RC4 Algorithm** 
## Thuật toán mã hoá RC4 là gì ?
Thuật toán RC4 là một thuật toán mã hóa dòng (stream cipher) được thiết kế bởi Ron Rivest vào năm 1987.

Với mã hoá RC4 thì dữ liệu sẽ được mã hóa bằng cách thực hiện phép XOR giữa từng byte của plaintext với một luồng khóa giả ngẫu nhiên (keystream) được sinh ra từ một khóa bí mật

## Nó hoạt động ra sao ?
RC4 yêu cầu cần có 1 khoá bí mật, khoá này thì dài **tối đa 256 byte**

Như đã đề cập bên trên thì RC4 sẽ **XOR** từng byte của thằng plaintext với **keystream** ngẫu nhiên. Vậy câu hỏi là cái thằng **keystream** lấy ở đâu ra ?

Thì nó được tạo từ thằng **khoá bí mật** chứ ở đâu ra nữa =)))

RC4 bao gồm 2 giai đoạn chính là : 
<pre>Khởi tạo mảng trạng thái (KSA - Key Scheduling Algorithm) 
Tạo luồng khóa (PRGA - Pseudo-Random Generation Algorithm) </pre>

## KSA 
- Quy trình : 
    - Chắc chắn sẽ phải có khoá bí mật rồi, mình sẽ gọi là `array key[]` và độ dài của nó là `key_Len`

    - Tiếp theo chúng ta cần chuẩn bị 1 mảng S-box như này `array S[] = [0, 1, 2, ..., 255] `

    - Đối với mỗi 1 phần tử trong `S[]` , ta sẽ tạo 1 giá trị `j = 0`, rồi tính `j` theo công thức, sau đó `swap S[j] và S[i]`

Mã giả code C++ như sau :  
<pre>
int j = 0;
for (int i = 0; i <= 255; i++) {
    j = (j + S[i] + key[i % key_Len]) % 256;
    swap(S[i], S[j]); 
}
</pre>
**⇒ Tạo được 1 mảng S-box ngẫu nhiên dựa theo khoá ban đầu** 


## PRGA
Sau khi đã tạo ra 1 chuỗi S-box ngẫu nhiên rồi thì nhiệm vụ tiếp theo là tạo 1 chuỗi byte ngẫu nhiên, hay còn gọi là `keystream` từ chính thằng S-box
- Quy trình : 
    - Khởi tạo 2 chỉ số ` i = j = 0 ` <p style="color:red;">NOTE : khởi tạo ngoài vòng lặp </p>
    - Tạo 1 vòng lặp bằng với độ dài của plaintext, và trong mỗi vòng lặp : 
        - `i = (i + 1) mod 256`
        - `j = (j + S[i]) mod 256`
        - swap `S[i]` và `S[j]`
        - Tính chỉ số `t = (S[i] + S[j]) mod 256` 
        - Lúc này ta có thể `XOR` luôn byte `S[t]` đó với byte cùng chỉ số tương ứng của plaintext hoặc lưu nó vào 1 mảng `key_Stream` riêng rồi mới `XOR`

Mã giả code C++ như sau :
<pre>
int key_len = strlen(key) ; 
int i = 0 , j = 0 ; 
for( int p = 0 ; p < key_len;  ++p){
    i = (i + 1) % 256 ;
    j = (j + S[i]) % 256 ; 
    swap(S[i],S[j]);
    int t = (S[i] + S[j]) mod 256;
    plaintext[p] ^= S[t];  // hết vòng for thì chuỗi plaintext sẽ trở thành đoạn bị encrypt
}
</pre>

## Decryption
Để giải mã thì đơn giản ta chỉ cần `XOR` lại cái `keystream` với `encrypted_data` là được

CODE C : [Here](https://ideone.com/jduS27?fbclid=IwY2xjawL8lRpleHRuA2FlbQIxMABicmlkETE3TGRyVXZCYWMyS2JvWmZ5AR5CmBRJASdzJ5J8e-ATgMB85l8zRwR2Qd0g9eFyOJS0rKlSBfNz4yYEvEbhaQ_aem_PmrP544ZY5cb8xDPwQlC6A)

*** 
## ***<p style="color:red;">by hieesu19</p>***
