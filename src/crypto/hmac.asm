; =============================================================================
; hmac.asm — HMAC-SHA-256 (RFC 2104)
;
; HMAC(K, m) = SHA256((K' XOR opad) || SHA256((K' XOR ipad) || m))
; K' = SHA256(K) if len(K) > 64, else K padded with zeros to 64 bytes
; ipad = 0x36 repeated 64 times
; opad = 0x5c repeated 64 times
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define SHA256_CTX_SIZE 112
%define HMAC_BLOCK_SIZE 64
%define HMAC_DIGEST_SIZE 32

section .text

extern _sha256_init
extern _sha256_update
extern _sha256_final
extern _sha256_hash

; hmac_sha256(key, key_len, msg, msg_len, out)
; rdi=key, rsi=key_len, rdx=msg, rcx=msg_len, r8=out (32 bytes)
global _hmac_sha256
_hmac_sha256:
    push rbp
    mov rbp, rsp
    ; Stack layout:
    ;   [rbp-64]  key_pad (64 bytes) — K' zero-padded
    ;   [rbp-128] ipad block (64 bytes)
    ;   [rbp-192] opad block (64 bytes)
    ;   [rbp-304] sha256 context (112 bytes)
    ;   [rbp-336] inner hash (32 bytes)
    sub rsp, 352            ; 336 + 16 alignment
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; key
    mov r13, rsi            ; key_len
    mov r14, rdx            ; msg
    mov r15, rcx            ; msg_len
    mov rbx, r8             ; output

    ; --- Step 1: Derive K' (key_pad) ---
    ; Zero key_pad first
    lea rdi, [rbp - 64]
    xor al, al
    mov ecx, 64
    rep stosb

    ; If key_len > 64, hash the key
    cmp r13, 64
    ja .hash_key

    ; key_len <= 64: copy key into key_pad
    lea rdi, [rbp - 64]
    mov rsi, r12
    mov rcx, r13
    rep movsb
    jmp .build_pads

.hash_key:
    ; key_len > 64: K' = SHA256(key)
    mov rdi, r12
    mov rsi, r13
    lea rdx, [rbp - 64]    ; store hash in first 32 bytes of key_pad
    call _sha256_hash

.build_pads:
    ; --- Step 2: Build ipad and opad ---
    xor ecx, ecx
.pad_loop:
    movzx eax, byte [rbp - 64 + rcx]   ; key_pad[i]
    mov edx, eax
    xor eax, 0x36
    mov [rbp - 128 + rcx], al           ; ipad[i] = key_pad[i] ^ 0x36
    xor edx, 0x5c
    mov [rbp - 192 + rcx], dl           ; opad[i] = key_pad[i] ^ 0x5c
    inc ecx
    cmp ecx, 64
    jl .pad_loop

    ; --- Step 3: Inner hash = SHA256(ipad || msg) ---
    lea rdi, [rbp - 304]
    call _sha256_init

    lea rdi, [rbp - 304]
    lea rsi, [rbp - 128]    ; ipad
    mov edx, 64
    call _sha256_update

    lea rdi, [rbp - 304]
    mov rsi, r14             ; msg
    mov rdx, r15             ; msg_len
    call _sha256_update

    lea rdi, [rbp - 304]
    lea rsi, [rbp - 336]    ; inner_hash output
    call _sha256_final

    ; --- Step 4: Outer hash = SHA256(opad || inner_hash) ---
    lea rdi, [rbp - 304]
    call _sha256_init

    lea rdi, [rbp - 304]
    lea rsi, [rbp - 192]    ; opad
    mov edx, 64
    call _sha256_update

    lea rdi, [rbp - 304]
    lea rsi, [rbp - 336]    ; inner_hash
    mov edx, 32
    call _sha256_update

    lea rdi, [rbp - 304]
    mov rsi, rbx             ; final output
    call _sha256_final

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret
