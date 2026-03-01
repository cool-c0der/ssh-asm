; =============================================================================
; main.asm — SSH server entry point
; Accept loop with fork-per-connection
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; SSH version string (sent to client, must end with \r\n)
    server_version: db "SSH-2.0-NasmSSH_1.0", 13, 10
    server_version_len equ $ - server_version
    ; Just the identifier part (without \r\n) for logging/hashing
    global server_version_id
    server_version_id: db "SSH-2.0-NasmSSH_1.0", 0
    server_version_id_len equ $ - server_version_id - 1

    msg_starting:   db "Starting SSH server on port 2222", 0
    msg_listening:  db "Listening for connections...", 0
    msg_accepted:   db "Connection accepted, forking child", 0
    msg_child:      db "Child process handling connection", 0
    msg_client_ver: db "Client version: ", 0
    msg_init_fail:  db "Failed to initialize memory allocator", 0
    msg_sock_fail:  db "Failed to create listening socket", 0
    msg_fork_fail:  db "Fork failed", 0
    msg_shutdown:   db "Shutdown signal received, exiting", 0
    msg_disconnecting: db "Disconnecting client", 0

section .bss
    ; Client version string buffer
    client_version_buf: resb 256

section .text

; External functions
extern _mem_init
extern _tcp_listen
extern _tcp_accept
extern _tcp_close
extern _setup_signals
extern _sys_exit
extern _sys_fork
extern _sys_close
extern _sys_read
extern _write_all
extern _read_line
extern _log_str
extern _log_msg
extern _shutdown_flag
extern _ssh_session_run

; Entry point
global _main
_main:
    FUNC_ENTER
    SAVE_CALLEE

    ; Initialize memory allocator
    call _mem_init
    test eax, eax
    jnz .init_fail

    ; Install signal handlers
    call _setup_signals

    ; Log startup
    lea rdi, [rel msg_starting]
    call _log_str

    ; Create listening socket on port 2222
    mov edi, DEFAULT_PORT
    call _tcp_listen
    test rax, rax
    js .sock_fail
    mov r12, rax            ; r12 = server_fd

    lea rdi, [rel msg_listening]
    call _log_str

; --- Main accept loop ---
.accept_loop:
    ; Check shutdown flag
    lea rax, [rel _shutdown_flag]
    cmp dword [rax], 0
    jne .shutdown

    ; Accept connection
    mov rdi, r12
    call _tcp_accept
    test rax, rax
    js .accept_loop         ; EINTR or error, retry
    mov r13, rax            ; r13 = client_fd

    lea rdi, [rel msg_accepted]
    call _log_str

    ; Fork
    call _sys_fork
    test rax, rax
    js .fork_fail
    jz .child               ; rax=0 -> child process

    ; --- Parent process ---
    ; Close client fd (child has it)
    mov rdi, r13
    call _sys_close
    jmp .accept_loop

; --- Child process ---
.child:
    ; Close server fd (parent owns it)
    mov rdi, r12
    call _sys_close

    lea rdi, [rel msg_child]
    call _log_str

    ; Send our SSH version string
    mov rdi, r13
    lea rsi, [rel server_version]
    mov rdx, server_version_len
    call _write_all
    test eax, eax
    jnz .child_exit

    ; Read client version string (must start with "SSH-2.0-")
    mov rdi, r13
    lea rsi, [rel client_version_buf]
    mov edx, 255
    call _read_line
    test rax, rax
    jle .child_exit
    mov r14, rax            ; r14 = bytes read

    ; Null-terminate (strip \r\n)
    lea rdi, [rel client_version_buf]
    ; Strip trailing \r\n
    cmp r14, 2
    jl .child_exit
    cmp byte [rdi + r14 - 1], 10   ; \n
    jne .no_strip_n
    dec r14
.no_strip_n:
    cmp byte [rdi + r14 - 1], 13   ; \r
    jne .no_strip_r
    dec r14
.no_strip_r:
    mov byte [rdi + r14], 0

    ; Log client version
    lea rdi, [rel msg_client_ver]
    call _log_str

    lea rdi, [rel client_version_buf]
    mov rsi, r14
    call _log_msg

    ; Validate client version starts with "SSH-2.0-"
    lea rdi, [rel client_version_buf]
    lea rsi, [rel ssh_prefix]
    mov edx, 8
    call _memcmp_simple
    test eax, eax
    jnz .child_exit         ; Invalid version, just disconnect

    ; Run full SSH session (key exchange, auth, channel, shell)
    mov edi, r13d            ; client_fd
    lea rsi, [rel client_version_buf]
    mov edx, r14d            ; client version length
    call _ssh_session_run

.child_exit:
    lea rdi, [rel msg_disconnecting]
    call _log_str

    ; Close client socket
    mov rdi, r13
    call _tcp_close

    ; Exit child process
    xor edi, edi
    call _sys_exit

; --- Error paths ---
.init_fail:
    lea rdi, [rel msg_init_fail]
    call _log_str
    mov edi, 1
    call _sys_exit

.sock_fail:
    lea rdi, [rel msg_sock_fail]
    call _log_str
    mov edi, 1
    call _sys_exit

.fork_fail:
    lea rdi, [rel msg_fork_fail]
    call _log_str
    ; Close client_fd and continue
    mov rdi, r13
    call _sys_close
    jmp .accept_loop

.shutdown:
    lea rdi, [rel msg_shutdown]
    call _log_str
    mov rdi, r12
    call _tcp_close
    xor edi, edi
    call _sys_exit

section .data
    ssh_prefix: db "SSH-2.0-", 0

section .text
; Simple memcmp (inline, no extern needed for bootstrap)
_memcmp_simple:
    mov rcx, rdx
    repe cmpsb
    je .eq
    movzx eax, byte [rdi-1]
    movzx ecx, byte [rsi-1]
    sub eax, ecx
    ret
.eq:
    xor eax, eax
    ret
