; =============================================================================
; signal.asm — Signal handlers for SIGCHLD, SIGPIPE, SIGTERM
;
; macOS __sigaction struct (for raw syscall 46):
;   offset 0:  sa_handler/sa_sigaction  (8 bytes)
;   offset 8:  sa_tramp                 (8 bytes) — trampoline function
;   offset 16: sa_mask                  (4 bytes)
;   offset 20: sa_flags                 (4 bytes)
; Total: 24 bytes
;
; The trampoline is called by the kernel as:
;   sa_tramp(void *uap, int style, int sig, siginfo_t *sinfo, void *handler)
;   rdi=uap, esi=style, edx=sig, rcx=sinfo, r8=handler
; It must call handler(sig) then __sigreturn(uap, style)
; =============================================================================

%include "constants.asm"
%include "macros.asm"

%define SYS_sigreturn (SYS_CLASS | 184)

section .data
    ; Flag set by SIGTERM handler
    global _shutdown_flag
    _shutdown_flag: dd 0

section .text

extern _sys_sigaction

; Signal trampoline — called by kernel for custom handlers
; rdi=uap, esi=style, edx=sig, rcx=sinfo, r8=handler_fn
; We need to: call handler(sig), then sigreturn(uap, style)
_signal_tramp:
    ; Save uap and style for sigreturn
    push rdi                ; save uap
    push rsi                ; save style

    ; Call handler(sig)
    ; edx = signal number, r8 = handler
    mov edi, edx            ; arg1 = signal number
    call r8                 ; call handler

    ; sigreturn(uap, style)
    pop rsi                 ; style
    pop rdi                 ; uap
    mov rax, SYS_sigreturn
    syscall
    ; Should never reach here
    ud2

; Simple signal handlers (don't need to preserve everything since
; the kernel/trampoline saves/restores context via ucontext)

; SIGCHLD handler — reap zombie children
_sigchld_handler:
    ; rdi = signal number (from trampoline)
    ; Save volatile regs used by wait4 syscall
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
.reap_loop:
    mov rdi, -1             ; any child
    xor esi, esi            ; status = NULL
    mov edx, WNOHANG        ; don't block
    xor r10d, r10d          ; rusage = NULL
    mov rax, SYS_wait4
    syscall
    jc .reap_done
    test rax, rax
    jg .reap_loop
.reap_done:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret

; SIGTERM/SIGINT handler — set shutdown flag
_sigterm_handler:
    ; rdi = signal number
    lea rax, [rel _shutdown_flag]
    mov dword [rax], 1
    ret

; setup_signals() — install signal handlers
global _setup_signals
_setup_signals:
    FUNC_ENTER 32           ; space for sigaction struct (24 bytes + padding)

    ; --- Ignore SIGPIPE ---
    ; For SIG_IGN, trampoline is not used (kernel handles it)
    lea rsi, [rbp - 32]
    mov qword [rsi], SIG_IGN        ; sa_handler = SIG_IGN
    mov qword [rsi + 8], 0          ; sa_tramp = NULL (not needed for SIG_IGN)
    mov dword [rsi + 16], 0         ; sa_mask = 0
    mov dword [rsi + 20], 0         ; sa_flags = 0
    mov edi, SIGPIPE
    xor edx, edx                    ; oldact = NULL
    call _sys_sigaction

    ; --- Ignore SIGCHLD (auto-reap zombies) ---
    ; Using SIG_IGN for SIGCHLD causes the kernel to auto-reap
    lea rsi, [rbp - 32]
    mov qword [rsi], SIG_IGN        ; sa_handler = SIG_IGN
    mov qword [rsi + 8], 0          ; sa_tramp
    mov dword [rsi + 16], 0         ; sa_mask
    mov dword [rsi + 20], 0         ; sa_flags
    mov edi, SIGCHLD
    xor edx, edx
    call _sys_sigaction

    ; --- SIGTERM: graceful shutdown ---
    lea rsi, [rbp - 32]
    lea rax, [rel _sigterm_handler]
    mov [rsi], rax                  ; sa_handler
    lea rax, [rel _signal_tramp]
    mov [rsi + 8], rax              ; sa_tramp
    mov dword [rsi + 16], 0         ; sa_mask
    mov dword [rsi + 20], SA_RESTART  ; sa_flags
    mov edi, SIGTERM
    xor edx, edx
    call _sys_sigaction

    ; --- SIGINT: graceful shutdown ---
    lea rsi, [rbp - 32]
    lea rax, [rel _sigterm_handler]
    mov [rsi], rax
    lea rax, [rel _signal_tramp]
    mov [rsi + 8], rax
    mov dword [rsi + 16], 0
    mov dword [rsi + 20], SA_RESTART
    mov edi, SIGINT
    xor edx, edx
    call _sys_sigaction

    FUNC_LEAVE
