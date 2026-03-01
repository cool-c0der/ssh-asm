; =============================================================================
; aes_ctr.asm — AES-CTR mode (SSH uses big-endian counter increment)
;
; SSH AES-CTR (RFC 4344): counter is a 128-bit big-endian integer
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
align 16
; Byte-swap mask for converting between LE xmm and BE counter
bswap_mask:
    db 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
; Constant 1 for counter increment
one:
    dq 1, 0

section .text

extern _aes_encrypt_block

; aes_ctr_crypt(schedule, n_rounds, iv, data, len)
; In-place encrypt/decrypt (CTR mode is symmetric)
; rdi = key schedule (aligned)
; esi = rounds (10 or 14)
; rdx = 16-byte IV/counter (modified in place — updated to next counter value)
; rcx = data buffer (in-place)
; r8  = data length
global _aes_ctr_crypt
_aes_ctr_crypt:
    push rbp
    mov rbp, rsp
    sub rsp, 48             ; space for counter block + encrypted block
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; schedule
    mov r13d, esi           ; n_rounds
    mov r14, rdx            ; IV/counter pointer
    mov r15, rcx            ; data
    mov rbx, r8             ; remaining length

.block_loop:
    test rbx, rbx
    jz .done

    ; Encrypt current counter value
    lea rcx, [rbp - 32]     ; output: encrypted counter
    mov rdi, r12             ; schedule
    mov esi, r13d            ; rounds
    mov rdx, r14             ; counter as plaintext
    call _aes_encrypt_block

    ; XOR encrypted counter with data (up to 16 bytes)
    mov ecx, 16
    cmp rbx, 16
    cmovb ecx, ebx          ; n = min(16, remaining)

    ; XOR loop
    xor eax, eax
.xor_loop:
    cmp eax, ecx
    jge .xor_done
    movzx edx, byte [rbp - 32 + rax]  ; encrypted counter byte
    xor dl, [r15 + rax]               ; XOR with data
    mov [r15 + rax], dl                ; store back
    inc eax
    jmp .xor_loop
.xor_done:

    ; Increment big-endian counter (128-bit)
    ; Counter is stored as big-endian bytes in memory
    ; We increment from the rightmost byte (offset 15)
    mov eax, 15
.inc_loop:
    inc byte [r14 + rax]
    jnz .inc_done           ; no carry, done
    dec eax
    jns .inc_loop            ; carry, continue to next byte
.inc_done:

    add r15, rcx             ; advance data pointer
    sub rbx, rcx             ; remaining -= n

    jmp .block_loop

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret
