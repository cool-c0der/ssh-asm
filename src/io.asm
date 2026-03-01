; =============================================================================
; io.asm — Buffered I/O + exact read/write helpers
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .text

extern _sys_read
extern _sys_write

; write_all(fd, buf, len) -> 0 on success, -1 on error
; Loops until all bytes written
; rdi=fd, rsi=buf, rdx=len
global _write_all
_write_all:
    FUNC_ENTER
    push rbx
    push r12
    push r13

    mov rbx, rdi        ; fd
    mov r12, rsi        ; buf
    mov r13, rdx        ; remaining

.loop:
    test r13, r13
    jz .done

    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call _sys_write
    test rax, rax
    jle .error          ; 0 = closed, <0 = error

    add r12, rax
    sub r13, rax
    jmp .loop

.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.error:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

; read_exact(fd, buf, len) -> 0 on success, -1 on error/eof
; Loops until all bytes read
; rdi=fd, rsi=buf, rdx=len
global _read_exact
_read_exact:
    FUNC_ENTER
    push rbx
    push r12
    push r13

    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx

.loop:
    test r13, r13
    jz .done

    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    call _sys_read
    test rax, rax
    jle .error

    add r12, rax
    sub r13, rax
    jmp .loop

.done:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.error:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

; read_line(fd, buf, maxlen) -> bytes read (including \n), 0 on EOF, -1 on error
; Reads one byte at a time until \n or maxlen
; rdi=fd, rsi=buf, rdx=maxlen
global _read_line
_read_line:
    FUNC_ENTER 8
    push rbx
    push r12
    push r13
    push r14

    mov rbx, rdi         ; fd
    mov r12, rsi         ; buf
    mov r13, rdx         ; maxlen
    xor r14d, r14d       ; bytes read

.loop:
    cmp r14, r13
    jge .done            ; buffer full

    ; Read one byte
    lea rsi, [r12 + r14]
    mov rdi, rbx
    mov rdx, 1
    call _sys_read
    test rax, rax
    jl .error
    jz .eof

    ; Check for \n
    cmp byte [r12 + r14], 10
    lea r14, [r14 + 1]  ; increment without clobbering flags
    je .done             ; found newline
    jmp .loop

.done:
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.eof:
    ; Return bytes read so far (could be 0)
    mov rax, r14
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.error:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE
