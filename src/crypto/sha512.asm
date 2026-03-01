; =============================================================================
; sha512.asm — SHA-512 (FIPS 180-4)
;
; Context layout (216 bytes):
;   [0..63]      8 x uint64 state (H0-H7)
;   [64..191]    128-byte block buffer
;   [192..199]   uint64 total bytes processed
;   [200..203]   uint32 buffer fill count
;   [204..215]   padding (alignment)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define SHA512_CTX_STATE    0
%define SHA512_CTX_BLOCK    64
%define SHA512_CTX_TOTAL    192
%define SHA512_CTX_BUFLEN   200
%define SHA512_CTX_SIZE     216

section .data
align 16
sha512_h0:
    dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
    dq 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
    dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f
    dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

align 16
sha512_k:
    dq 0x428a2f98d728ae22, 0x7137449123ef65cd
    dq 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
    dq 0x3956c25bf348b538, 0x59f111f1b605d019
    dq 0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    dq 0xd807aa98a3030242, 0x12835b0145706fbe
    dq 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1
    dq 0x9bdc06a725c71235, 0xc19bf174cf692694
    dq 0xe49b69c19ef14ad2, 0xefbe4786384f25e3
    dq 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
    dq 0x2de92c6f592b0275, 0x4a7484aa6ea6e483
    dq 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210
    dq 0xb00327c898fb213f, 0xbf597fc7beef0ee4
    dq 0xc6e00bf33da88fc2, 0xd5a79147930aa725
    dq 0x06ca6351e003826f, 0x142929670a0e6e70
    dq 0x27b70a8546d22ffc, 0x2e1b21385c26c926
    dq 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8
    dq 0x81c2c92e47edaee6, 0x92722c851482353b
    dq 0xa2bfe8a14cf10364, 0xa81a664bbc423001
    dq 0xc24b8b70d0f89791, 0xc76c51a30654be30
    dq 0xd192e819d6ef5218, 0xd69906245565a910
    dq 0xf40e35855771202a, 0x106aa07032bbd1b8
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53
    dq 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
    dq 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
    dq 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
    dq 0x748f82ee5defb2fc, 0x78a5636f43172f60
    dq 0x84c87814a1f0ab72, 0x8cc702081a6439ec
    dq 0x90befffa23631e28, 0xa4506cebde82bde9
    dq 0xbef9a3f7b2c67915, 0xc67178f2e372532b
    dq 0xca273eceea26619c, 0xd186b8c721c0c207
    dq 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
    dq 0x06f067aa72176fba, 0x0a637dc5a2c898a6
    dq 0x113f9804bef90dae, 0x1b710b35131c471b
    dq 0x28db77f523047d84, 0x32caab7b40c72493
    dq 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
    dq 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
    dq 0x5fcb6fab3ad6faec, 0x6c44198c4a475817

section .text

; sha512_init(ctx)
global _sha512_init
_sha512_init:
    ; Copy 8 initial hash values (64-bit each)
    lea rsi, [sha512_h0]
    mov ecx, 8
.init_loop:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec ecx
    jnz .init_loop
    sub rdi, 64
    mov qword [rdi + SHA512_CTX_TOTAL], 0
    mov dword [rdi + SHA512_CTX_BUFLEN], 0
    ret

; _sha512_transform(ctx)
; Process the 128-byte block at ctx+SHA512_CTX_BLOCK
; W[80] = 640 bytes, working vars a-h = 64 bytes
_sha512_transform:
    push rbp
    mov rbp, rsp
    ; W[80]=640 + wv[8]=64 = 704, align to 16 = 720
    sub rsp, 720
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rdi            ; ctx pointer

    ; W[0..15]: load block words as big-endian (64-bit)
    lea rsi, [r15 + SHA512_CTX_BLOCK]
    xor ecx, ecx
.load_w:
    mov rax, [rsi + rcx*8]
    bswap rax
    mov [rbp - 640 + rcx*8], rax
    inc ecx
    cmp ecx, 16
    jl .load_w

    ; W[16..79]: message schedule expansion
    mov ecx, 16
.expand:
    ; sigma1 = ROTR14(W[t-2]) ^ ROTR18(W[t-2]) ^ SHR6(W[t-2])
    mov rax, [rbp - 640 + rcx*8 - 16]   ; W[t-2]
    mov rdx, rax
    mov r8, rax
    ror rax, 19
    ror rdx, 61
    shr r8, 6
    xor rax, rdx
    xor rax, r8            ; sigma1

    ; + W[t-7]
    add rax, [rbp - 640 + rcx*8 - 56]

    ; sigma0 = ROTR1(W[t-15]) ^ ROTR8(W[t-15]) ^ SHR7(W[t-15])
    mov rdx, [rbp - 640 + rcx*8 - 120]  ; W[t-15]
    mov r8, rdx
    mov r9, rdx
    ror rdx, 1
    ror r8, 8
    shr r9, 7
    xor rdx, r8
    xor rdx, r9            ; sigma0
    add rax, rdx

    ; + W[t-16]
    add rax, [rbp - 640 + rcx*8 - 128]
    mov [rbp - 640 + rcx*8], rax

    inc ecx
    cmp ecx, 80
    jl .expand

    ; Initialize working variables a..h from state
    ; Store at [rbp-704] (8 x 8 = 64 bytes)
    xor ecx, ecx
.init_wv:
    mov rax, [r15 + rcx*8]
    mov [rbp - 704 + rcx*8], rax
    inc ecx
    cmp ecx, 8
    jl .init_wv

    ; 80 rounds
    lea r14, [sha512_k]
    xor r12d, r12d

.round:
    ; T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t]

    ; Sigma1(e) = ROTR14(e) ^ ROTR18(e) ^ ROTR41(e)
    mov rax, [rbp - 704 + 32]       ; e
    mov rdx, rax
    mov r8, rax
    ror rax, 14
    ror rdx, 18
    ror r8, 41
    xor rax, rdx
    xor rax, r8                     ; Sigma1(e)

    ; Ch(e,f,g) = (e & f) ^ (~e & g)
    mov rdx, [rbp - 704 + 32]       ; e
    mov rcx, rdx
    not rcx                          ; ~e
    and rdx, [rbp - 704 + 40]       ; e & f
    and rcx, [rbp - 704 + 48]       ; ~e & g
    xor rdx, rcx                    ; Ch(e,f,g)

    ; T1 = sum
    add rax, [rbp - 704 + 56]       ; + h
    add rax, rdx                    ; + Ch
    add rax, [r14 + r12*8]          ; + K[t]
    add rax, [rbp - 640 + r12*8]    ; + W[t]
    mov rbx, rax                    ; rbx = T1

    ; T2 = Sigma0(a) + Maj(a,b,c)

    ; Sigma0(a) = ROTR28(a) ^ ROTR34(a) ^ ROTR39(a)
    mov rax, [rbp - 704]            ; a
    mov rdx, rax
    mov r8, rax
    ror rax, 28
    ror rdx, 34
    ror r8, 39
    xor rax, rdx
    xor rax, r8                     ; Sigma0(a)

    ; Maj(a,b,c) = (a & b) ^ (a & c) ^ (b & c)
    mov rdx, [rbp - 704]            ; a
    mov rcx, [rbp - 704 + 8]        ; b
    mov r8, [rbp - 704 + 16]        ; c
    mov r9, rdx
    and r9, rcx                     ; a & b
    mov r10, rdx
    and r10, r8                     ; a & c
    xor r9, r10
    and rcx, r8                     ; b & c
    xor r9, rcx                     ; Maj(a,b,c)

    add rax, r9                     ; T2

    ; Update working variables
    ; h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
    mov rcx, [rbp - 704 + 48]
    mov [rbp - 704 + 56], rcx       ; h = g
    mov rcx, [rbp - 704 + 40]
    mov [rbp - 704 + 48], rcx       ; g = f
    mov rcx, [rbp - 704 + 32]
    mov [rbp - 704 + 40], rcx       ; f = e
    mov rcx, [rbp - 704 + 24]
    add rcx, rbx
    mov [rbp - 704 + 32], rcx       ; e = d + T1
    mov rcx, [rbp - 704 + 16]
    mov [rbp - 704 + 24], rcx       ; d = c
    mov rcx, [rbp - 704 + 8]
    mov [rbp - 704 + 16], rcx       ; c = b
    mov rcx, [rbp - 704]
    mov [rbp - 704 + 8], rcx        ; b = a
    lea rcx, [rbx + rax]
    mov [rbp - 704], rcx            ; a = T1 + T2

    inc r12d
    cmp r12d, 80
    jl .round

    ; Add working variables back to state
    xor ecx, ecx
.add_back:
    mov rax, [rbp - 704 + rcx*8]
    add [r15 + rcx*8], rax
    inc ecx
    cmp ecx, 8
    jl .add_back

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

; sha512_update(ctx, data, len)
global _sha512_update
_sha512_update:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi            ; ctx
    mov r13, rsi            ; data ptr
    mov r14, rdx            ; remaining len

    ; Track total
    add [r12 + SHA512_CTX_TOTAL], r14

.uloop:
    test r14, r14
    jz .udone

    ; Space left in block buffer
    mov eax, [r12 + SHA512_CTX_BUFLEN]
    mov ebx, 128
    sub ebx, eax            ; space = 128 - buflen

    ; n = min(space, remaining)
    cmp r14, rbx
    jae .ufull
    mov ebx, r14d
.ufull:
    ; Copy n bytes from data to block buffer
    mov eax, [r12 + SHA512_CTX_BUFLEN]
    lea rdi, [r12 + SHA512_CTX_BLOCK]
    add rdi, rax
    mov rsi, r13
    mov ecx, ebx
    rep movsb

    add r13, rbx
    sub r14, rbx
    add [r12 + SHA512_CTX_BUFLEN], ebx

    ; If block is full (128 bytes), transform
    cmp dword [r12 + SHA512_CTX_BUFLEN], 128
    jne .uloop

    mov rdi, r12
    call _sha512_transform
    mov dword [r12 + SHA512_CTX_BUFLEN], 0
    jmp .uloop

.udone:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; sha512_final(ctx, digest)
global _sha512_final
_sha512_final:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r12, rdi            ; ctx
    mov r13, rsi            ; digest output (64 bytes)

    ; Append padding byte 0x80
    mov eax, [r12 + SHA512_CTX_BUFLEN]
    lea rdi, [r12 + SHA512_CTX_BLOCK]
    mov byte [rdi + rax], 0x80
    inc eax

    ; Zero remaining bytes in block
    lea rdi, [r12 + SHA512_CTX_BLOCK]
    add rdi, rax
    mov ecx, 128
    sub ecx, eax
    jle .pad_extra_block
    push rax
    xor al, al
    rep stosb
    pop rax

    ; Check if room for 16-byte length (need pos <= 112)
    cmp eax, 113
    jl .pad_write_len

.pad_extra_block:
    mov rdi, r12
    call _sha512_transform
    ; Zero entire block
    lea rdi, [r12 + SHA512_CTX_BLOCK]
    xor al, al
    mov ecx, 128
    rep stosb

.pad_write_len:
    ; Write total bit count as big-endian uint128 at block[112..127]
    ; High 64 bits = 0 (we don't support >2^64 byte messages)
    mov qword [r12 + SHA512_CTX_BLOCK + 112], 0
    ; Low 64 bits = total_bytes * 8
    mov rax, [r12 + SHA512_CTX_TOTAL]
    shl rax, 3
    bswap rax
    mov [r12 + SHA512_CTX_BLOCK + 120], rax

    ; Final transform
    mov rdi, r12
    call _sha512_transform

    ; Copy state to digest (big-endian output)
    xor ecx, ecx
.out:
    mov rax, [r12 + rcx*8]
    bswap rax
    mov [r13 + rcx*8], rax
    inc ecx
    cmp ecx, 8
    jl .out

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; sha512_hash(data, len, digest) — one-shot convenience
global _sha512_hash
_sha512_hash:
    push rbp
    mov rbp, rsp
    sub rsp, 224            ; context (216 needed, 224 for alignment)
    push r12
    push r13
    push r14

    mov r12, rdi            ; data
    mov r13, rsi            ; len
    mov r14, rdx            ; digest

    lea rdi, [rbp - 224]
    call _sha512_init

    lea rdi, [rbp - 224]
    mov rsi, r12
    mov rdx, r13
    call _sha512_update

    lea rdi, [rbp - 224]
    mov rsi, r14
    call _sha512_final

    pop r14
    pop r13
    pop r12
    leave
    ret
