; =============================================================================
; log.asm — Stderr logging with timestamps
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    log_prefix: db "[ssh-asm] ", 0
    log_prefix_len equ $ - log_prefix - 1

section .bss
    log_buf: resb 512

section .text

extern _sys_write
extern _sys_gettimeofday
extern _itoa_dec
extern _memcpy
extern _strlen

; log_msg(msg, len) — write "[ssh-asm] <msg>\n" to stderr
; rdi=msg, rsi=len
global _log_msg
_log_msg:
    FUNC_ENTER
    push rbx
    push r12

    mov rbx, rdi         ; msg
    mov r12, rsi         ; len

    ; Build log line in log_buf
    lea rdi, [rel log_buf]
    lea rsi, [rel log_prefix]
    mov rdx, log_prefix_len
    call _memcpy

    ; Copy message
    lea rdi, [rel log_buf + log_prefix_len]
    mov rsi, rbx
    mov rdx, r12
    ; Cap at buffer size
    lea rax, [r12 + log_prefix_len + 1]
    cmp rax, 511
    jbe .copy
    mov rdx, 511 - log_prefix_len - 1
    mov r12, rdx
.copy:
    call _memcpy

    ; Add newline
    lea rax, [log_prefix_len + r12]
    lea rdi, [rel log_buf]
    mov byte [rdi + rax], 10    ; '\n'
    inc rax

    ; Write to stderr
    mov rdi, 2
    lea rsi, [rel log_buf]
    mov rdx, rax
    call _sys_write

    pop r12
    pop rbx
    FUNC_LEAVE

; log_str(null_terminated_str) — convenience wrapper
; rdi=str (null-terminated)
global _log_str
_log_str:
    FUNC_ENTER
    push rbx
    mov rbx, rdi
    call _strlen
    mov rsi, rax
    mov rdi, rbx
    call _log_msg
    pop rbx
    FUNC_LEAVE

; log_hex(prefix, data, len) — log a hex dump
; rdi=prefix (null-terminated), rsi=data, rdx=len
global _log_hex
_log_hex:
    FUNC_ENTER
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi         ; prefix
    mov r12, rsi         ; data
    mov r13, rdx         ; len

    ; Write prefix to log_buf
    lea rdi, [rel log_buf]
    lea rsi, [rel log_prefix]
    mov rdx, log_prefix_len
    call _memcpy

    ; Copy prefix string
    mov rdi, rbx
    call _strlen
    mov r14, rax         ; prefix len

    lea rdi, [rel log_buf + log_prefix_len]
    mov rsi, rbx
    mov rdx, r14
    call _memcpy

    ; Add hex bytes (limited to fit buffer)
    lea rbx, [rel log_buf + log_prefix_len]
    add rbx, r14
    xor ecx, ecx
.hex_loop:
    cmp ecx, r13d
    jge .hex_done
    ; Check buffer space (2 chars per byte + spaces)
    lea rax, [rbx + 3]
    lea rdx, [rel log_buf + 510]
    cmp rax, rdx
    jge .hex_done

    movzx eax, byte [r12 + rcx]
    push rcx
    mov rdi, rbx
    mov sil, al
    extern _hex_byte
    call _hex_byte
    pop rcx
    add rbx, 2
    mov byte [rbx], ' '
    inc rbx
    inc ecx
    jmp .hex_loop

.hex_done:
    mov byte [rbx], 10    ; newline
    inc rbx

    ; Write to stderr
    mov rdi, 2
    lea rsi, [rel log_buf]
    lea rdx, [rel log_buf]
    sub rbx, rdx          ; total length
    mov rdx, rbx
    call _sys_write

    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE
