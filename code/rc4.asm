section .data
    hStdIn      dd 0           
    hStdOut     dd 0           
    
    keyMsg      db 'Nhap key: ', 0
    keyMsgLen   equ $ - keyMsg - 1
    
    plaintextMsg db 'Nhap plaintext: ', 0
    plaintextMsgLen equ $ - plaintextMsg - 1
    
    resultMsg   db 'Ma hoa (HEX): ', 0
    resultMsgLen equ $ - resultMsg - 1
    
    newline     db 13, 10, 0
    newlineLen  equ $ - newline - 1

section .bss
    s        resb 256        ; mảng s RC4 (256 byte)
    key   resb 256        ; buffer lưu key
    text  resb 1024       ; buffer lưu plaintext/ciphertext
    hex   resb 2048       ; buffer lưu kết quả hex
    
    bytesRead   resd 1          ; số byte đã đọc
    bytesWritten resd 1         ; số byte đã ghi
    keyLen      resd 1          ; độ dài key
    textLen     resd 1          ; độ dài text
    
    i           resb 1          ; chỉ số i của RC4
    j           resb 1          ; chỉ số j của RC4
    temp        resb 1          ; biến tạm

section .text
    global _start   
    extern GetStdHandle
    extern WriteConsoleA
    extern ReadConsoleA
    extern ExitProcess

_start:
    push -10
    call GetStdHandle
    mov [hStdIn], eax
    
    push -11
    call GetStdHandle
    mov [hStdOut], eax
    
    call get_key
    call get_plaintext
    call rc4_init
    call rc4_encrypt
    call display_hex_result
    
    push 0
    call ExitProcess

get_key:
    ; hiển thị thông báo nhập key
    push 0
    push bytesWritten
    push keyMsgLen
    push keyMsg
    push dword [hStdOut]
    call WriteConsoleA
    
    ; đọc key từ bàn phím
    push 0
    push bytesRead
    push 255
    push key
    push dword [hStdIn]
    call ReadConsoleA
    
    ; xóa ký tự xuống dòng và lưu độ dài key
    mov eax, [bytesRead]
    dec eax                     ; bỏ CR
    dec eax                     ; bỏ LF
    mov [keyLen], eax
    mov ebx, key
    add ebx, eax
    mov byte [ebx], 0           ; thêm null terminator
    
    ret

get_plaintext:
    ; hiển thị thông báo nhập plaintext
    push 0
    push bytesWritten
    push plaintextMsgLen
    push plaintextMsg
    push dword [hStdOut]
    call WriteConsoleA
    
    ; đọc plaintext từ bàn phím
    push 0
    push bytesRead
    push 1023
    push text
    push dword [hStdIn]
    call ReadConsoleA
    
    ; xóa ký tự xuống dòng và lưu độ dài text
    mov eax, [bytesRead]
    dec eax                     ; bỏ CR
    dec eax                     ; bỏ LF
    mov [textLen], eax
    mov ebx, text
    add ebx, eax
    mov byte [ebx], 0           ; thêm null terminator
    
    ret

rc4_init:
    ; khởi tạo sbox với (S[i] = i)
    xor eax, eax
init_loop1:
    mov [s + eax], al
    inc eax
    cmp eax, 256
    jl init_loop1
    
    ; trộn sbox với key 
    xor eax, eax                ; i = 0
    xor ebx, ebx                ; j = 0
    
init_loop2:
    ; tính j = (j + S[i] + key[i % keylen]) % 256
    movzx ecx, byte [s + eax] ; lấy S[i]
    add ebx, ecx                ; j += S[i]
    
    ; lấy byte key tại vị trí i % keylen
    push eax
    push ebx
    
    xor edx, edx
    mov ecx, [keyLen]
    div ecx                     ; i / keyLen, phần dư trong edx
    movzx ecx, byte [key + edx] ; key[i % keylen]
    
    pop ebx
    pop eax
    
    add ebx, ecx                ; j += key[i % keylen]
    and ebx, 0xFF               ; j % 256
    
    ; swap S[i] va S[j]
    mov cl, [s + eax]
    mov ch, [s + ebx]
    mov [s + eax], ch
    mov [s + ebx], cl
    
    inc eax
    cmp eax, 256
    jl init_loop2
    
    ; tạo biến đếm cho prga
    mov byte [i], 0
    mov byte [j], 0
    
    ret

rc4_encrypt:
    mov esi, text         ; con trỏ nguồn
    mov edi, text         ; con trỏ đích (mã hóa tại chỗ)
    mov ecx, [textLen]          ; số byte cần mã hóa
    
encrypt_loop:
    cmp ecx, 0
    je encrypt_done
    
    ; cập nhật i: i = (i + 1) % 256
    movzx eax, byte [i]
    inc eax
    and eax, 0xFF
    mov [i], al
    
    ; cập nhật j: j = (j + S[i]) % 256
    movzx ebx, byte [s + eax]
    movzx edx, byte [j]
    add edx, ebx
    and edx, 0xFF
    mov [j], dl
    
    ; swap S[i] và S[j]
    mov bl, [s + eax]
    mov bh, [s + edx]
    mov [s + eax], bh
    mov [s + edx], bl
    
    ; tạo byte keystream: K = S[(S[i] + S[j]) % 256]
    movzx eax, bl               ; S[i] cũ
    movzx edx, bh               ; S[j] cũ
    add eax, edx                ; S[i] + S[j]
    and eax, 0xFF
    mov al, [s + eax]        ; K = S[(S[i] + S[j]) % 256]
    
    ; mã hóa: ciphertext = plaintext XOR keystream
    xor al, [esi]
    mov [edi], al
    
    ; Chuyển đến byte tiếp theo
    inc esi
    inc edi
    dec ecx
    jmp encrypt_loop
    
encrypt_done:
    ret

display_hex_result:
    push 0
    push bytesWritten
    push resultMsgLen
    push resultMsg
    push dword [hStdOut]
    call WriteConsoleA
    
    ; đổi từng byte -> hex
    mov esi, text
    mov edi, hex
    mov ecx, [textLen]
    
hex_loop:
    cmp ecx, 0
    je hex_done
    
    movzx eax, byte [esi]       ; lấy byte cần chuyển đổi
    
    ; chuyển đổi nibble cao (4 bit trên)
    mov bl, al
    shr bl, 4                   ; lấy 4 bit cao
    push eax
    mov al, bl
    call nibble_to_hex
    mov [edi], al
    inc edi
    pop eax
    
    ; chuyển đổi nibble thấp (4 bit dưới)
    and al, 0x0F                ; lấy 4 bit thấp
    call nibble_to_hex
    mov [edi], al
    inc edi
    
    inc esi
    dec ecx
    jmp hex_loop
    
hex_done:
    ; tính độ dài chuỗi hex (mỗi byte = 2 ký tự hex)
    mov eax, [textLen]
    shl eax, 1
    
    ; hiển thị chuỗi hex
    push 0
    push bytesWritten
    push eax
    push hex
    push dword [hStdOut]
    call WriteConsoleA
    
    ; thêm xuống dòng
    push 0
    push bytesWritten
    push newlineLen
    push newline
    push dword [hStdOut]
    call WriteConsoleA
    
    ret

nibble_to_hex:
    ; chuyển đổi nibble (0-15) thành ký tự hex
    cmp al, 9
    jle hex_digit
    add al, 'A' - 10            ; 10-15 -> 'A'-'F'
    ret
hex_digit:
    add al, '0'                 ; 0-9 -> '0'-'9'
    ret