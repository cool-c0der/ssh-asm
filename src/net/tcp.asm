; =============================================================================
; net/tcp.asm — TCP socket operations
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; sockaddr_in for binding (16 bytes on macOS)
    ; struct sockaddr_in { uint8 len, uint8 family, uint16 port, uint32 addr, uint8 zero[8] }
    bind_addr:
        db 16               ; sin_len (macOS specific)
        db AF_INET           ; sin_family
        dw 0                 ; sin_port (filled at runtime, network byte order)
        dd 0                 ; sin_addr = INADDR_ANY
        dq 0                 ; padding

    ; For setsockopt
    opt_val: dd 1

section .text

extern _sys_socket
extern _sys_bind
extern _sys_listen
extern _sys_accept
extern _sys_setsockopt
extern _sys_close
extern _sys_shutdown
extern _sys_getpeername
extern _log_str
extern _log_msg
extern _itoa_dec

; tcp_listen(port) -> server_fd or -1
; rdi = port number (host byte order)
global _tcp_listen
_tcp_listen:
    FUNC_ENTER
    push rbx
    push r12

    ; Store port in network byte order
    mov ax, di
    xchg al, ah              ; swap to big-endian
    lea rcx, [rel bind_addr + 2]
    mov [rcx], ax

    ; socket(AF_INET, SOCK_STREAM, 0)
    mov edi, AF_INET
    mov esi, SOCK_STREAM
    xor edx, edx
    call _sys_socket
    test rax, rax
    js .fail
    mov rbx, rax             ; server_fd

    ; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4)
    mov rdi, rbx
    mov esi, SOL_SOCKET
    mov edx, SO_REUSEADDR
    lea r10, [rel opt_val]
    mov r8d, 4
    call _sys_setsockopt
    ; Ignore error, not fatal

    ; setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &1, 4)
    mov rdi, rbx
    mov esi, SOL_SOCKET
    mov edx, SO_REUSEPORT
    lea r10, [rel opt_val]
    mov r8d, 4
    call _sys_setsockopt

    ; bind(fd, &bind_addr, 16)
    mov rdi, rbx
    lea rsi, [rel bind_addr]
    mov edx, 16
    call _sys_bind
    test rax, rax
    js .fail_close

    ; listen(fd, LISTEN_BACKLOG)
    mov rdi, rbx
    mov esi, LISTEN_BACKLOG
    call _sys_listen
    test rax, rax
    js .fail_close

    mov rax, rbx             ; return server_fd
    pop r12
    pop rbx
    FUNC_LEAVE

.fail_close:
    mov rdi, rbx
    call _sys_close
.fail:
    mov rax, -1
    pop r12
    pop rbx
    FUNC_LEAVE

; tcp_accept(server_fd) -> client_fd or -1
; rdi = server_fd
global _tcp_accept
_tcp_accept:
    FUNC_ENTER 32
    push rbx

    mov rbx, rdi

    ; accept(fd, NULL, NULL) — we don't need peer addr yet
    mov rdi, rbx
    xor esi, esi
    xor edx, edx
    call _sys_accept
    ; rax = client_fd or -errno

    pop rbx
    FUNC_LEAVE

; tcp_close(fd)
; rdi = fd
global _tcp_close
_tcp_close:
    FUNC_ENTER

    ; shutdown(fd, SHUT_RDWR) — ignore errors
    push rdi
    mov esi, SHUT_RDWR
    call _sys_shutdown
    pop rdi

    ; close(fd)
    call _sys_close

    FUNC_LEAVE
