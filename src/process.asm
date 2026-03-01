; =============================================================================
; process.asm — Process management wrappers
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .text

extern _sys_fork
extern _sys_execve
extern _sys_wait4
extern _sys_setsid
extern _sys_dup2
extern _sys_close
extern _sys_chdir

; proc_fork() -> pid (0=child, >0=parent, <0=error)
global _proc_fork
_proc_fork:
    jmp _sys_fork

; proc_setsid() -> session_id or -1
global _proc_setsid
_proc_setsid:
    jmp _sys_setsid

; proc_dup2(oldfd, newfd) -> newfd or -1
global _proc_dup2
_proc_dup2:
    jmp _sys_dup2

; proc_execve(path, argv, envp) -> does not return on success, -1 on error
global _proc_execve
_proc_execve:
    jmp _sys_execve

; proc_wait_nohang(status_ptr) -> pid of reaped child, 0 if none, -1 on error
; rdi = pointer to int for status (can be NULL)
global _proc_wait_nohang
_proc_wait_nohang:
    mov rsi, rdi         ; status ptr
    mov rdi, -1          ; wait for any child
    mov edx, WNOHANG
    xor r10d, r10d       ; rusage = NULL
    jmp _sys_wait4
