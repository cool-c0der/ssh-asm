; =============================================================================
; chacha20.asm — ChaCha20 stream cipher (RFC 8439)
;
; State: 16 x uint32 in a 4x4 matrix
;   [0..3]  = "expand 32-byte k" (constants)
;   [4..11] = 256-bit key (8 words)
;   [12]    = block counter
;   [13..15] = 96-bit nonce (3 words)
;
; Quarter-round: a += b; d ^= a; d <<<= 16;
;                c += d; b ^= c; b <<<= 12;
;                a += b; d ^= a; d <<<= 8;
;                c += d; b ^= c; b <<<= 7;
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
align 16
; "expand 32-byte k" as 4 little-endian uint32
chacha20_const:
    dd 0x61707865   ; "expa"
    dd 0x3320646e   ; "nd 3"
    dd 0x79622d32   ; "2-by"
    dd 0x6b206574   ; "te k"

section .text

; chacha20_block(key, counter, nonce, output)
; Compute one 64-byte keystream block
; rdi = 32-byte key
; esi = 32-bit block counter
; rdx = 12-byte nonce
; rcx = 64-byte output buffer
global _chacha20_block
_chacha20_block:
    push rbp
    mov rbp, rsp
    sub rsp, 128             ; state[16] + working[16] = 128 bytes
    push rbx
    push r12

    mov r12, rcx             ; save output ptr

    ; Initialize state at [rbp-64]
    ; Constants
    lea rax, [chacha20_const]
    mov ecx, [rax]
    mov [rbp - 64], ecx
    mov ecx, [rax + 4]
    mov [rbp - 60], ecx
    mov ecx, [rax + 8]
    mov [rbp - 56], ecx
    mov ecx, [rax + 12]
    mov [rbp - 52], ecx

    ; Key (8 words from rdi)
    xor eax, eax
.load_key:
    mov ecx, [rdi + rax*4]
    mov [rbp - 48 + rax*4], ecx
    inc eax
    cmp eax, 8
    jl .load_key

    ; Counter
    mov [rbp - 16], esi

    ; Nonce (3 words from rdx)
    mov ecx, [rdx]
    mov [rbp - 12], ecx
    mov ecx, [rdx + 4]
    mov [rbp - 8], ecx
    mov ecx, [rdx + 8]
    mov [rbp - 4], ecx

    ; Copy state to working copy at [rbp-128]
    xor eax, eax
.copy_state:
    mov ecx, [rbp - 64 + rax*4]
    mov [rbp - 128 + rax*4], ecx
    inc eax
    cmp eax, 16
    jl .copy_state

    ; 20 rounds (10 double-rounds)
    mov ebx, 10
.double_round:
    ; Column rounds
    ; QR(0, 4,  8, 12)
    lea rdi, [rbp - 128]
    mov esi, 0
    mov edx, 4
    mov ecx, 8
    mov r8d, 12
    call .quarter_round

    ; QR(1, 5,  9, 13)
    lea rdi, [rbp - 128]
    mov esi, 1
    mov edx, 5
    mov ecx, 9
    mov r8d, 13
    call .quarter_round

    ; QR(2, 6, 10, 14)
    lea rdi, [rbp - 128]
    mov esi, 2
    mov edx, 6
    mov ecx, 10
    mov r8d, 14
    call .quarter_round

    ; QR(3, 7, 11, 15)
    lea rdi, [rbp - 128]
    mov esi, 3
    mov edx, 7
    mov ecx, 11
    mov r8d, 15
    call .quarter_round

    ; Diagonal rounds
    ; QR(0, 5, 10, 15)
    lea rdi, [rbp - 128]
    mov esi, 0
    mov edx, 5
    mov ecx, 10
    mov r8d, 15
    call .quarter_round

    ; QR(1, 6, 11, 12)
    lea rdi, [rbp - 128]
    mov esi, 1
    mov edx, 6
    mov ecx, 11
    mov r8d, 12
    call .quarter_round

    ; QR(2, 7,  8, 13)
    lea rdi, [rbp - 128]
    mov esi, 2
    mov edx, 7
    mov ecx, 8
    mov r8d, 13
    call .quarter_round

    ; QR(3, 4,  9, 14)
    lea rdi, [rbp - 128]
    mov esi, 3
    mov edx, 4
    mov ecx, 9
    mov r8d, 14
    call .quarter_round

    dec ebx
    jnz .double_round

    ; Add original state to working state, write to output
    xor eax, eax
.add_output:
    mov ecx, [rbp - 128 + rax*4]  ; working
    add ecx, [rbp - 64 + rax*4]   ; + original
    mov [r12 + rax*4], ecx         ; output (little-endian)
    inc eax
    cmp eax, 16
    jl .add_output

    pop r12
    pop rbx
    leave
    ret

; Quarter round on state[a], state[b], state[c], state[d]
; rdi = state base, esi = a_idx, edx = b_idx, ecx = c_idx, r8d = d_idx
.quarter_round:
    ; Load values
    mov eax, [rdi + rsi*4]       ; a
    mov r9d, [rdi + rdx*4]       ; b
    mov r10d, [rdi + rcx*4]      ; c
    mov r11d, [rdi + r8*4]       ; d

    ; a += b; d ^= a; d <<<= 16
    add eax, r9d
    xor r11d, eax
    rol r11d, 16

    ; c += d; b ^= c; b <<<= 12
    add r10d, r11d
    xor r9d, r10d
    rol r9d, 12

    ; a += b; d ^= a; d <<<= 8
    add eax, r9d
    xor r11d, eax
    rol r11d, 8

    ; c += d; b ^= c; b <<<= 7
    add r10d, r11d
    xor r9d, r10d
    rol r9d, 7

    ; Store back
    mov [rdi + rsi*4], eax
    mov [rdi + rdx*4], r9d
    mov [rdi + rcx*4], r10d
    mov [rdi + r8*4], r11d
    ret

; chacha20_crypt(key, counter, nonce, data, len)
; In-place encrypt/decrypt
; rdi = 32-byte key, esi = initial counter, rdx = 12-byte nonce
; rcx = data buffer, r8 = length
global _chacha20_crypt
_chacha20_crypt:
    push rbp
    mov rbp, rsp
    sub rsp, 80              ; 64-byte keystream block + 16 padding
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi             ; key
    mov r13d, esi            ; counter
    mov r14, rdx             ; nonce
    mov r15, rcx             ; data
    mov rbx, r8              ; remaining

.crypt_loop:
    test rbx, rbx
    jz .crypt_done

    ; Generate keystream block
    mov rdi, r12
    mov esi, r13d
    mov rdx, r14
    lea rcx, [rbp - 80]
    call _chacha20_block

    ; XOR with data (up to 64 bytes)
    mov ecx, 64
    cmp rbx, 64
    cmovb ecx, ebx

    xor eax, eax
.xor_loop:
    cmp eax, ecx
    jge .xor_done
    movzx edx, byte [rbp - 80 + rax]
    xor dl, [r15 + rax]
    mov [r15 + rax], dl
    inc eax
    jmp .xor_loop
.xor_done:

    add r15, rcx
    sub rbx, rcx
    inc r13d                 ; next block counter

    jmp .crypt_loop

.crypt_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret
