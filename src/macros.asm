; =============================================================================
; macros.asm — Function prologue/epilogue, syscall wrapper, debug macros
; =============================================================================

; --- Function prologue: save rbp + callee-saved registers ---
; Usage: FUNC_ENTER <local_bytes>
; Allocates stack space for local variables
%macro FUNC_ENTER 0-1 0
    push rbp
    mov rbp, rsp
%if %1 > 0
    sub rsp, %1
%endif
%endmacro

; --- Function epilogue ---
%macro FUNC_LEAVE 0
    leave
    ret
%endmacro

; --- macOS syscall: rax=number, args rdi/rsi/rdx/r10/r8/r9 ---
; Sets carry flag on error, rax = errno on failure
; Usage: SYSCALL <number>
%macro SYSCALL 1
    mov rax, %1
    syscall
%endmacro

; --- Check syscall result, jump to label on error ---
; After syscall, CF=1 means error, rax=errno
%macro CHECK_SYSCALL 1
    jc %1
%endmacro

; --- Save/restore callee-saved registers ---
%macro SAVE_CALLEE 0
    push rbx
    push r12
    push r13
    push r14
    push r15
%endmacro

%macro RESTORE_CALLEE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
%endmacro

; --- Push and pop multiple registers for function calls ---
%macro PUSH_VOLATILE 0
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
%endmacro

%macro POP_VOLATILE 0
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
%endmacro

; --- Write a string literal to stderr (for debug) ---
; Usage: LOG_STR "message here"
%macro LOG_STR 1
    section .data
%%msg: db %1, 10  ; 10 = newline
%%len equ $ - %%msg
    section .text
    push rdi
    push rsi
    push rdx
    push rax
    mov rdi, 2          ; stderr
    lea rsi, [rel %%msg]
    mov rdx, %%len
    SYSCALL SYS_write
    pop rax
    pop rdx
    pop rsi
    pop rdi
%endmacro

; --- Write uint32 in network byte order (big-endian) to memory ---
; Usage: STORE_BE32 <dest_reg>, <value_reg>
; Trashes rax
%macro STORE_BE32 2
    mov eax, %2
    bswap eax
    mov [%1], eax
%endmacro

; --- Read uint32 from network byte order ---
; Usage: LOAD_BE32 <dest_reg>, <src_mem>
%macro LOAD_BE32 2
    mov %1, [%2]
    bswap %1
%endmacro

; --- Align stack to 16 bytes before call (macOS ABI requirement) ---
%macro ALIGN_STACK 0
    and rsp, -16
%endmacro

; --- Zero a register ---
%macro ZERO 1
    xor %1, %1
%endmacro
