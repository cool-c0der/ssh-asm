; =============================================================================
; sha256.asm — SHA-256 (FIPS 180-4)
;
; Context layout (112 bytes):
;   [0..31]    8 x uint32 state (H0-H7)
;   [32..95]   64-byte block buffer
;   [96..103]  uint64 total bytes processed
;   [104..107] uint32 buffer fill count
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define SHA256_CTX_STATE    0
%define SHA256_CTX_BLOCK    32
%define SHA256_CTX_TOTAL    96
%define SHA256_CTX_BUFLEN   104
%define SHA256_CTX_SIZE     112

section .data
align 16
sha256_h0:
    dd 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    dd 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

align 16
sha256_k:
    dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    dd 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    dd 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    dd 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    dd 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    dd 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    dd 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    dd 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    dd 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    dd 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    dd 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

section .text

; sha256_init(ctx)
global _sha256_init
_sha256_init:
    ; Copy 8 initial hash values
    lea rsi, [sha256_h0]
    mov ecx, 8
.init_loop:
    mov eax, [rsi]
    mov [rdi], eax
    add rsi, 4
    add rdi, 4
    dec ecx
    jnz .init_loop
    sub rdi, 32
    mov qword [rdi + SHA256_CTX_TOTAL], 0
    mov dword [rdi + SHA256_CTX_BUFLEN], 0
    ret

; _sha256_transform(ctx)
; Process the 64-byte block at ctx+SHA256_CTX_BLOCK
; Uses stack for W[64] and working variables
_sha256_transform:
    push rbp
    mov rbp, rsp
    ; Allocate: W[64]=256 bytes + wv[8]=32 bytes + 16 padding = 304
    ; Then 5 callee-saved pushes = 40 bytes extra
    ; Total from rbp: 304 + 40 = 344
    sub rsp, 352            ; 304 + 48 for alignment/pushes
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r15, rdi            ; ctx pointer

    ; W[0..15]: load block words as big-endian
    lea rsi, [r15 + SHA256_CTX_BLOCK]
    xor ecx, ecx
.load_w:
    mov eax, [rsi + rcx*4]
    bswap eax
    mov [rbp - 256 + rcx*4], eax
    inc ecx
    cmp ecx, 16
    jl .load_w

    ; W[16..63]: message schedule expansion
    mov ecx, 16
.expand:
    ; s1 = ROTR17(W[t-2]) ^ ROTR19(W[t-2]) ^ SHR10(W[t-2])
    mov eax, [rbp - 256 + rcx*4 - 8]
    mov edx, eax
    mov r8d, eax
    ror eax, 17
    ror edx, 19
    shr r8d, 10
    xor eax, edx
    xor eax, r8d
    ; + W[t-7]
    add eax, [rbp - 256 + rcx*4 - 28]
    ; s0 = ROTR7(W[t-15]) ^ ROTR18(W[t-15]) ^ SHR3(W[t-15])
    mov edx, [rbp - 256 + rcx*4 - 60]
    mov r8d, edx
    mov r9d, edx
    ror edx, 7
    ror r8d, 18
    shr r9d, 3
    xor edx, r8d
    xor edx, r9d
    add eax, edx
    ; + W[t-16]
    add eax, [rbp - 256 + rcx*4 - 64]
    mov [rbp - 256 + rcx*4], eax
    inc ecx
    cmp ecx, 64
    jl .expand

    ; Initialize working variables a..h from state
    ; Store at [rbp-288] through [rbp-257] (8 * 4 = 32 bytes)
    xor ecx, ecx
.init_wv:
    mov eax, [r15 + rcx*4]
    mov [rbp - 288 + rcx*4], eax
    inc ecx
    cmp ecx, 8
    jl .init_wv

    ; 64 rounds
    lea r14, [sha256_k]
    xor r12d, r12d

.round:
    ; ---- T1 = h + Sigma1(e) + Ch(e,f,g) + K[t] + W[t] ----

    ; Sigma1(e) = ROTR6(e) ^ ROTR11(e) ^ ROTR25(e)
    mov eax, [rbp - 288 + 16]       ; e
    mov edx, eax
    mov r8d, eax
    ror eax, 6
    ror edx, 11
    ror r8d, 25
    xor eax, edx
    xor eax, r8d                    ; eax = Sigma1(e)

    ; Ch(e,f,g) = (e AND f) XOR (NOT e AND g)
    mov edx, [rbp - 288 + 16]       ; e
    mov ecx, edx
    not ecx                          ; ~e
    and edx, [rbp - 288 + 20]       ; e & f
    and ecx, [rbp - 288 + 24]       ; ~e & g
    xor edx, ecx                    ; Ch(e,f,g)

    ; T1 = sum of all components
    add eax, [rbp - 288 + 28]       ; + h
    add eax, edx                    ; + Ch
    add eax, [r14 + r12*4]          ; + K[t]
    add eax, [rbp - 256 + r12*4]    ; + W[t]
    mov ebx, eax                    ; ebx = T1

    ; ---- T2 = Sigma0(a) + Maj(a,b,c) ----

    ; Sigma0(a) = ROTR2(a) ^ ROTR13(a) ^ ROTR22(a)
    mov eax, [rbp - 288]            ; a
    mov edx, eax
    mov r8d, eax
    ror eax, 2
    ror edx, 13
    ror r8d, 22
    xor eax, edx
    xor eax, r8d                    ; eax = Sigma0(a)

    ; Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c)
    mov edx, [rbp - 288]            ; a
    mov ecx, [rbp - 288 + 4]        ; b
    mov r8d, [rbp - 288 + 8]        ; c
    mov r9d, edx
    and r9d, ecx                    ; a & b
    mov r10d, edx
    and r10d, r8d                   ; a & c
    xor r9d, r10d
    and ecx, r8d                    ; b & c
    xor r9d, ecx                    ; Maj(a,b,c)

    add eax, r9d                    ; eax = T2

    ; ---- Update working variables ----
    ; h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2
    mov ecx, [rbp - 288 + 24]
    mov [rbp - 288 + 28], ecx       ; h = g
    mov ecx, [rbp - 288 + 20]
    mov [rbp - 288 + 24], ecx       ; g = f
    mov ecx, [rbp - 288 + 16]
    mov [rbp - 288 + 20], ecx       ; f = e
    mov ecx, [rbp - 288 + 12]
    add ecx, ebx
    mov [rbp - 288 + 16], ecx       ; e = d + T1
    mov ecx, [rbp - 288 + 8]
    mov [rbp - 288 + 12], ecx       ; d = c
    mov ecx, [rbp - 288 + 4]
    mov [rbp - 288 + 8], ecx        ; c = b
    mov ecx, [rbp - 288]
    mov [rbp - 288 + 4], ecx        ; b = a
    lea ecx, [ebx + eax]            ; T1 + T2
    mov [rbp - 288], ecx            ; a = T1 + T2

    inc r12d
    cmp r12d, 64
    jl .round

    ; Add working variables back to state
    xor ecx, ecx
.add_back:
    mov eax, [rbp - 288 + rcx*4]
    add [r15 + rcx*4], eax
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

; sha256_update(ctx, data, len)
global _sha256_update
_sha256_update:
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
    add [r12 + SHA256_CTX_TOTAL], r14

.uloop:
    test r14, r14
    jz .udone

    ; Space left in block buffer
    mov eax, [r12 + SHA256_CTX_BUFLEN]
    mov ebx, 64
    sub ebx, eax            ; space = 64 - buflen

    ; n = min(space, remaining)
    cmp r14, rbx
    jae .ufull
    mov ebx, r14d           ; n = remaining (less than space)
.ufull:
    ; Copy n bytes from data to block buffer
    mov eax, [r12 + SHA256_CTX_BUFLEN]
    lea rdi, [r12 + SHA256_CTX_BLOCK]
    add rdi, rax             ; dst = block + buflen
    mov rsi, r13             ; src = data
    mov ecx, ebx             ; count
    rep movsb

    add r13, rbx             ; advance data
    sub r14, rbx             ; remaining -= n
    add [r12 + SHA256_CTX_BUFLEN], ebx  ; buflen += n

    ; If block is full, transform
    cmp dword [r12 + SHA256_CTX_BUFLEN], 64
    jne .uloop

    mov rdi, r12
    call _sha256_transform
    mov dword [r12 + SHA256_CTX_BUFLEN], 0
    jmp .uloop

.udone:
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; sha256_final(ctx, digest)
global _sha256_final
_sha256_final:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r12, rdi            ; ctx
    mov r13, rsi            ; digest output

    ; Append padding byte 0x80
    mov eax, [r12 + SHA256_CTX_BUFLEN]
    lea rdi, [r12 + SHA256_CTX_BLOCK]
    mov byte [rdi + rax], 0x80
    inc eax

    ; Zero remaining bytes in block
    lea rdi, [r12 + SHA256_CTX_BLOCK]
    add rdi, rax
    mov ecx, 64
    sub ecx, eax
    jle .pad_noroom
    push rax
    xor al, al
    rep stosb
    pop rax

    ; Check if room for 8-byte length (need pos <= 56)
    cmp eax, 57
    jl .pad_write_len
    ; No room — transform this block and start fresh
    jmp .pad_extra_block

.pad_noroom:
    ; eax = 64 (buffer was full after 0x80 at position 63)
    ; Must transform and use new block for length
.pad_extra_block:
    mov rdi, r12
    call _sha256_transform
    ; Zero entire block
    lea rdi, [r12 + SHA256_CTX_BLOCK]
    xor al, al
    mov ecx, 64
    rep stosb

.pad_write_len:
    ; Write total bit count as big-endian uint64 at block[56..63]
    mov rax, [r12 + SHA256_CTX_TOTAL]
    shl rax, 3              ; bytes to bits
    bswap rax               ; to big-endian
    mov [r12 + SHA256_CTX_BLOCK + 56], rax

    ; Final transform
    mov rdi, r12
    call _sha256_transform

    ; Copy state to digest (big-endian output)
    xor ecx, ecx
.out:
    mov eax, [r12 + rcx*4]
    bswap eax
    mov [r13 + rcx*4], eax
    inc ecx
    cmp ecx, 8
    jl .out

    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; sha256_hash(data, len, digest) — one-shot convenience
global _sha256_hash
_sha256_hash:
    push rbp
    mov rbp, rsp
    sub rsp, 128            ; context (112 needed, 128 for alignment)
    push r12
    push r13
    push r14

    mov r12, rdi            ; data
    mov r13, rsi            ; len
    mov r14, rdx            ; digest

    lea rdi, [rbp - 128]
    call _sha256_init

    lea rdi, [rbp - 128]
    mov rsi, r12
    mov rdx, r13
    call _sha256_update

    lea rdi, [rbp - 128]
    mov rsi, r14
    call _sha256_final

    pop r14
    pop r13
    pop r12
    leave
    ret
