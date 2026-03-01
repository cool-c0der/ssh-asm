; =============================================================================
; pty.asm — macOS PTY allocation
;
; macOS PTY flow:
;   1. posix_openpt(O_RDWR) -> master fd
;   2. grantpt(master) via ioctl TIOCPTYGRANT
;   3. unlockpt(master) via ioctl TIOCPTYUNLK
;   4. ptsname(master) via ioctl with TIOCPTYGNAME -> slave path
;   5. open(slave_path, O_RDWR | O_NOCTTY) -> slave fd
;
; Functions:
;   pty_open(channel) -> 0 or -1
;   pty_set_winsize(channel) -> 0 or -1
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

; macOS TIOCPTYGNAME ioctl: _IOC(IOC_OUT, 't', 0x43, 128)
; = 0x40807453 on macOS (returns 128-byte path string)
%define TIOCPTYGNAME 0x40807453

section .data
    dev_ptmx:        db "/dev/ptmx", 0
    msg_pty_open:    db "Opening PTY", 0
    msg_pty_master:  db "PTY master fd: ", 0
    msg_pty_slave:   db "PTY slave: ", 0
    msg_pty_fail:    db "PTY open failed", 0
    msg_pty_grant:   db "PTY grant failed", 0
    msg_pty_unlock:  db "PTY unlock failed", 0
    msg_pty_name:    db "PTY name failed", 0
    msg_pty_sopen:   db "PTY slave open failed", 0

section .bss
    pty_slave_path: resb 128    ; path from TIOCPTYGNAME

section .text

extern _sys_posix_openpt
extern _sys_ioctl
extern _sys_open
extern _sys_close
extern _log_str
extern _log_msg
extern _itoa_dec

; pty_open(channel) -> 0 or -1
; Opens a PTY pair and stores fds in channel structure
; rdi = channel pointer (256 bytes)
global _pty_open
_pty_open:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    push rbx
    push r12
    push r13

    mov r12, rdi            ; channel

    lea rdi, [rel msg_pty_open]
    call _log_str

    ; 1. open("/dev/ptmx", O_RDWR) -> master fd
    ; (posix_openpt is a libc wrapper, not a raw macOS syscall)
    lea rdi, [rel dev_ptmx]
    mov esi, O_RDWR
    xor edx, edx
    call _sys_open
    test rax, rax
    js .pty_fail
    mov r13d, eax            ; master fd
    mov [r12 + CHAN_PTY_MASTER], r13d

    ; 2. grantpt(master) via ioctl TIOCPTYGRANT
    mov edi, r13d
    mov rsi, TIOCPTYGRANT
    xor edx, edx
    call _sys_ioctl
    test rax, rax
    js .pty_grant_fail

    ; 3. unlockpt(master) via ioctl TIOCPTYUNLK
    mov edi, r13d
    mov rsi, TIOCPTYUNLK
    xor edx, edx
    call _sys_ioctl
    test rax, rax
    js .pty_unlock_fail

    ; 4. ptsname via TIOCPTYGNAME
    mov edi, r13d
    mov rsi, TIOCPTYGNAME
    lea rdx, [pty_slave_path]
    call _sys_ioctl
    test rax, rax
    js .pty_name_fail

    ; Copy slave path to channel
    lea rdi, [r12 + CHAN_PTY_NAME]
    lea rsi, [pty_slave_path]
    mov ecx, 64              ; max path length in channel struct
    rep movsb

    ; Log slave path
    lea rdi, [rel msg_pty_slave]
    call _log_str
    lea rdi, [pty_slave_path]
    call _log_str

    ; 5. Open slave
    lea rdi, [pty_slave_path]
    mov esi, O_RDWR | O_NOCTTY
    xor edx, edx
    call _sys_open
    test rax, rax
    js .pty_slave_fail
    mov [r12 + CHAN_PTY_SLAVE], eax

    xor eax, eax
    jmp .pty_done

.pty_fail:
    lea rdi, [rel msg_pty_fail]
    call _log_str
    mov eax, -1
    jmp .pty_done

.pty_grant_fail:
    lea rdi, [rel msg_pty_grant]
    call _log_str
    mov eax, -1
    jmp .pty_done

.pty_unlock_fail:
    lea rdi, [rel msg_pty_unlock]
    call _log_str
    mov eax, -1
    jmp .pty_done

.pty_name_fail:
    lea rdi, [rel msg_pty_name]
    call _log_str
    mov eax, -1
    jmp .pty_done

.pty_slave_fail:
    lea rdi, [rel msg_pty_sopen]
    call _log_str
    mov eax, -1

.pty_done:
    pop r13
    pop r12
    pop rbx
    add rsp, 32
    pop rbp
    ret

; pty_set_winsize(channel) -> 0 or -1
; Set terminal size from channel's TERM_ROWS/TERM_COLS
; rdi = channel pointer
global _pty_set_winsize
_pty_set_winsize:
    push rbp
    mov rbp, rsp
    sub rsp, 16             ; struct winsize (8 bytes) + padding

    mov eax, [rdi + CHAN_PTY_MASTER]
    cmp eax, -1
    je .ws_skip

    ; Build struct winsize on stack
    ; { unsigned short ws_row, ws_col, ws_xpixel, ws_ypixel }
    movzx ecx, word [rdi + CHAN_TERM_ROWS]
    mov [rbp - 8], cx           ; ws_row
    movzx ecx, word [rdi + CHAN_TERM_COLS]
    mov [rbp - 6], cx           ; ws_col
    movzx ecx, word [rdi + CHAN_TERM_XPIXEL]
    mov [rbp - 4], cx           ; ws_xpixel
    movzx ecx, word [rdi + CHAN_TERM_YPIXEL]
    mov [rbp - 2], cx           ; ws_ypixel

    ; ioctl(master_fd, TIOCSWINSZ, &winsize)
    mov edi, eax             ; master fd
    mov rsi, TIOCSWINSZ
    lea rdx, [rbp - 8]
    call _sys_ioctl

.ws_skip:
    xor eax, eax
    add rsp, 16
    pop rbp
    ret
