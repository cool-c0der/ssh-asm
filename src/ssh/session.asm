; =============================================================================
; session.asm — SSH Session Orchestrator
;
; Runs the entire SSH protocol sequence for a single connection:
;   1. Version exchange (already done in main.asm, versions stored in session)
;   2. Key exchange (KEXINIT + ECDH)
;   3. NEWKEYS + key derivation
;   4. User authentication
;   5. Channel open
;   6. Handle channel requests (PTY, shell)
;   7. Data forwarding loop: poll(socket, pty_master)
;
; Data flow loop:
;   poll([socket_fd, pty_master_fd], 2, timeout)
;     socket readable -> ssh_packet_recv -> if CHANNEL_DATA -> write to PTY
;     PTY readable -> read -> ssh_channel_send_data to client
;     PTY POLLHUP -> send CHANNEL_EOF + CHANNEL_CLOSE, exit
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
    msg_session_start:  db "SSH session starting", 0
    msg_session_end:    db "SSH session ended", 0
    msg_session_error:  db "SSH session error", 0
    msg_version_stored: db "Version strings stored", 0
    msg_shell_started:  db "Shell process started", 0
    msg_poll_loop:      db "Entering data forwarding loop", 0
    msg_child_exit:     db "Shell process exited", 0

    ; Server version string (for session init)
    sess_server_ver:    db "SSH-2.0-NasmSSH_1.0", 0
    sess_server_ver_len equ $ - sess_server_ver - 1

    ; Shell to execute
    shell_path:     db "/bin/sh", 0
    shell_argv0:    db "-sh", 0

    ; Environment variables
    env_term:       db "TERM=xterm-256color", 0
    env_path:       db "PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", 0
    env_home:       db "HOME=/tmp", 0

section .bss
    ; poll structure: struct pollfd { int fd; short events; short revents; }
    ; 2 entries = 16 bytes
    poll_fds:   resb 16
    ; Read buffer for PTY data
    pty_read_buf: resb 16384
    ; Recv buffer for SSH packets
    sess_recv_payload: resb 35000

section .text

extern _ssh_kex_exchange
extern _ssh_newkeys
extern _ssh_auth
extern _ssh_channel_open
extern _ssh_channel_handle_request
extern _ssh_channel_send_data
extern _ssh_channel_send_eof
extern _ssh_channel_send_close
extern _ssh_packet_send
extern _ssh_packet_recv
extern _read_be32
extern _write_be32
extern _mem_alloc_zeroed
extern _log_str
extern _log_msg
extern _sys_poll
extern _sys_read
extern _sys_write
extern _sys_fork
extern _sys_close
extern _sys_dup2
extern _sys_execve
extern _sys_setsid
extern _sys_ioctl
extern _memcpy
extern _memset
extern _ed25519_publickey
extern _random_bytes
extern _pty_open
extern chan_payload_buf

; ssh_session_run(client_fd, client_version, client_version_len)
; Run a complete SSH session
; edi = client fd
; rsi = client version string (without \r\n)
; edx = client version length
global _ssh_session_run
_ssh_session_run:
    push rbp
    mov rbp, rsp
    sub rsp, 256
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Save arguments first (before any function calls)
    mov [rbp - 16], edi     ; client_fd
    mov [rbp - 24], rsi     ; client_version
    mov [rbp - 32], edx     ; client_version_len

    lea rdi, [rel msg_session_start]
    call _log_str

    ; Allocate session structure (zeroed)
    mov rdi, SESS_SIZE
    call _mem_alloc_zeroed
    test rax, rax
    jz .session_error
    mov r12, rax            ; r12 = session pointer

    ; Restore saved arguments
    mov eax, [rbp - 16]
    mov [r12 + SESS_FD], eax
    mov dword [r12 + SESS_STATE], 1      ; kex state

    ; Store client version (without \r\n)
    mov r14, [rbp - 24]     ; client_version
    mov r15d, [rbp - 32]    ; client_version_len

    lea rdi, [r12 + SESS_CLIENT_VERSION]
    mov rsi, r14
    mov ecx, r15d
    cmp ecx, 255
    jbe .cv_ok
    mov ecx, 255
.cv_ok:
    rep movsb
    mov [r12 + SESS_CLIENT_VERSION_LEN], r15d

    ; Store server version (without \r\n)
    lea rdi, [r12 + SESS_SERVER_VERSION]
    lea rsi, [rel sess_server_ver]
    mov ecx, sess_server_ver_len
    rep movsb
    mov dword [r12 + SESS_SERVER_VERSION_LEN], sess_server_ver_len

    ; Generate host key (Ed25519)
    lea rdi, [r12 + SESS_HOST_KEY_PRIV]
    mov rsi, 32
    call _random_bytes

    lea rdi, [r12 + SESS_HOST_KEY_PRIV]
    lea rsi, [r12 + SESS_HOST_KEY_PUB]
    call _ed25519_publickey

    lea rdi, [rel msg_version_stored]
    call _log_str

    ; --- Phase 1: Key Exchange ---
    mov rdi, r12
    call _ssh_kex_exchange
    test eax, eax
    jnz .session_error

    ; --- Phase 2: NEWKEYS + Key Derivation ---
    mov rdi, r12
    call _ssh_newkeys
    test eax, eax
    jnz .session_error

    ; --- Phase 3: User Authentication ---
    mov rdi, r12
    call _ssh_auth
    test eax, eax
    jnz .session_error

    ; --- Phase 4: Channel Management ---
    mov rdi, r12
    call _ssh_channel_open
    test eax, eax
    jnz .session_error

    ; --- Phase 5: Handle channel requests until shell is requested ---
.wait_shell:
    mov rdi, r12
    lea rsi, [rbp - 1]          ; out_type
    lea rdx, [sess_recv_payload] ; out_payload
    lea rcx, [rbp - 8]          ; out_len
    call _ssh_packet_recv
    test eax, eax
    jnz .session_error

    movzx eax, byte [rbp - 1]

    ; Handle different message types
    cmp al, SSH_MSG_CHANNEL_REQUEST
    jne .not_chan_req

    mov rdi, r12
    lea rsi, [sess_recv_payload]
    mov edx, [rbp - 8]
    call _ssh_channel_handle_request
    cmp eax, 1
    je .shell_requested
    cmp eax, -1
    je .session_error
    jmp .wait_shell

.not_chan_req:
    cmp al, SSH_MSG_IGNORE
    je .wait_shell
    cmp al, SSH_MSG_DEBUG
    je .wait_shell
    cmp al, SSH_MSG_CHANNEL_WINDOW_ADJUST
    jne .not_window_adjust_pre

    lea rdi, [sess_recv_payload + 4]
    call _read_be32
    lea rdi, [r12 + SESS_CHANNELS]
    add [rdi + CHAN_REMOTE_WINDOW], eax
    jmp .wait_shell

.not_window_adjust_pre:
    cmp al, SSH_MSG_GLOBAL_REQUEST
    jne .wait_shell

    mov rdi, r12
    mov esi, SSH_MSG_REQUEST_FAILURE
    xor edx, edx
    xor ecx, ecx
    call _ssh_packet_send
    jmp .wait_shell

.shell_requested:
    lea rdi, [rel msg_shell_started]
    call _log_str

    ; --- Phase 6: Spawn shell ---
    ; If no PTY was opened (client didn't send pty-req), open one now
    lea rdi, [r12 + SESS_CHANNELS]
    cmp dword [rdi + CHAN_PTY_MASTER], -1
    jne .pty_ready
    call _pty_open
    test eax, eax
    jnz .session_error
    lea rdi, [r12 + SESS_CHANNELS]
.pty_ready:
    mov r13d, [rdi + CHAN_PTY_MASTER]
    mov r14d, [rdi + CHAN_PTY_SLAVE]

    call _sys_fork
    test rax, rax
    js .session_error
    jz .shell_child

    ; --- Parent: data forwarding ---
    mov [r12 + SESS_CHANNELS + CHAN_CHILD_PID], eax

    ; Close slave fd in parent
    mov edi, r14d
    call _sys_close

    jmp .data_loop_start

.shell_child:
    ; Child: become session leader, set controlling terminal
    call _sys_setsid

    ; Close master fd
    mov edi, r13d
    call _sys_close

    ; Set controlling terminal
    mov edi, r14d
    mov rsi, TIOCSCTTY
    xor edx, edx
    call _sys_ioctl

    ; Dup slave to stdin/stdout/stderr
    mov edi, r14d
    xor esi, esi
    call _sys_dup2
    mov edi, r14d
    mov esi, 1
    call _sys_dup2
    mov edi, r14d
    mov esi, 2
    call _sys_dup2

    ; Close original slave fd if > 2
    cmp r14d, 2
    jle .no_close_slave
    mov edi, r14d
    call _sys_close
.no_close_slave:

    ; Close the SSH socket fd
    mov edi, [r12 + SESS_FD]
    call _sys_close

    ; Build argv: ["-sh", NULL] and envp on stack
    sub rsp, 80
    lea rax, [rel shell_argv0]
    mov [rsp], rax
    mov qword [rsp + 8], 0
    lea rax, [rel env_term]
    mov [rsp + 16], rax
    lea rax, [rel env_path]
    mov [rsp + 24], rax
    lea rax, [rel env_home]
    mov [rsp + 32], rax
    mov qword [rsp + 40], 0

    ; execve("/bin/sh", argv, envp)
    lea rdi, [rel shell_path]
    mov rsi, rsp             ; argv
    lea rdx, [rsp + 16]     ; envp
    call _sys_execve

    ; If execve returns, exit with error
    mov edi, 127
    mov rax, SYS_exit
    syscall

; --- Data forwarding loop ---
.data_loop_start:
    lea rdi, [rel msg_poll_loop]
    call _log_str

.data_loop:
    ; Set up poll fds
    mov eax, [r12 + SESS_FD]
    mov [poll_fds], eax
    mov word [poll_fds + 4], POLLIN
    mov word [poll_fds + 6], 0
    mov [poll_fds + 8], r13d
    mov word [poll_fds + 12], POLLIN
    mov word [poll_fds + 14], 0

    lea rdi, [poll_fds]
    mov esi, 2
    mov edx, 30000
    call _sys_poll
    test rax, rax
    js .data_loop_error
    jz .data_loop

    ; Check PTY master (entry 1)
    movzx eax, word [poll_fds + 14]
    test ax, POLLHUP
    jnz .pty_closed
    test ax, POLLIN
    jz .check_socket

    ; PTY has data -> read and send to client
    mov edi, r13d
    lea rsi, [pty_read_buf]
    mov edx, 16384
    call _sys_read
    test rax, rax
    jle .pty_closed

    mov rdi, r12
    lea rsi, [pty_read_buf]
    mov edx, eax
    call _ssh_channel_send_data
    test eax, eax
    jnz .data_loop_error

.check_socket:
    movzx eax, word [poll_fds + 6]
    test ax, POLLHUP | POLLERR
    jnz .client_disconnected
    test ax, POLLIN
    jz .data_loop

    ; Socket has data -> receive SSH packet
    mov rdi, r12
    lea rsi, [rbp - 1]
    lea rdx, [sess_recv_payload]
    lea rcx, [rbp - 8]
    call _ssh_packet_recv
    test eax, eax
    jnz .client_disconnected

    movzx eax, byte [rbp - 1]

    cmp al, SSH_MSG_CHANNEL_DATA
    je .handle_channel_data
    cmp al, SSH_MSG_CHANNEL_WINDOW_ADJUST
    je .handle_window_adjust
    cmp al, SSH_MSG_CHANNEL_EOF
    je .data_loop
    cmp al, SSH_MSG_CHANNEL_CLOSE
    je .handle_channel_close
    cmp al, SSH_MSG_CHANNEL_REQUEST
    je .handle_channel_request_in_loop
    cmp al, SSH_MSG_IGNORE
    je .data_loop
    cmp al, SSH_MSG_DEBUG
    je .data_loop
    cmp al, SSH_MSG_DISCONNECT
    je .client_disconnected
    cmp al, SSH_MSG_GLOBAL_REQUEST
    jne .data_loop
    mov rdi, r12
    mov esi, SSH_MSG_REQUEST_FAILURE
    xor edx, edx
    xor ecx, ecx
    call _ssh_packet_send
    jmp .data_loop

.handle_channel_data:
    lea rdi, [sess_recv_payload + 4]
    call _read_be32
    mov ebx, eax

    mov edi, r13d
    lea rsi, [sess_recv_payload + 8]
    mov edx, ebx
    call _sys_write

    ; Send WINDOW_ADJUST
    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax
    mov eax, ebx
    bswap eax
    mov [rdi + 4], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_WINDOW_ADJUST
    lea rdx, [chan_payload_buf]
    mov ecx, 8
    call _ssh_packet_send
    jmp .data_loop

.handle_window_adjust:
    lea rdi, [sess_recv_payload + 4]
    call _read_be32
    lea rdi, [r12 + SESS_CHANNELS]
    add [rdi + CHAN_REMOTE_WINDOW], eax
    jmp .data_loop

.handle_channel_request_in_loop:
    mov rdi, r12
    lea rsi, [sess_recv_payload]
    mov edx, [rbp - 8]
    call _ssh_channel_handle_request
    jmp .data_loop

.handle_channel_close:
    mov rdi, r12
    call _ssh_channel_send_close
    jmp .session_end

.pty_closed:
    lea rdi, [rel msg_child_exit]
    call _log_str
    mov rdi, r12
    call _ssh_channel_send_eof
    mov rdi, r12
    call _ssh_channel_send_close
    jmp .session_end

.client_disconnected:
.data_loop_error:
.session_error:
    lea rdi, [rel msg_session_error]
    call _log_str

.session_end:
    lea rdi, [rel msg_session_end]
    call _log_str

    ; Cleanup: close PTY master if open
    cmp r13d, 0
    jle .no_close_master
    mov edi, r13d
    call _sys_close
.no_close_master:

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 256
    pop rbp
    ret
