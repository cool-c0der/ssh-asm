; =============================================================================
; random.asm — getentropy() wrapper for cryptographic randomness
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

extern _sys_getentropy

; random_bytes(buf, len) -> 0 on success, -1 on error
; rdi=buf, rsi=len
; getentropy() max is 256 bytes per call, so we loop
global _random_bytes
_random_bytes:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13

    mov r12, rdi            ; buf
    mov r13, rsi            ; remaining

.loop:
    test r13, r13
    jz .done

    ; Chunk = min(256, remaining)
    mov rsi, r13
    cmp rsi, 256
    jbe .call
    mov rsi, 256
.call:
    mov rbx, rsi            ; save chunk size
    mov rdi, r12
    call _sys_getentropy
    test rax, rax
    js .fail

    add r12, rbx
    sub r13, rbx
    jmp .loop

.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

.fail:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
