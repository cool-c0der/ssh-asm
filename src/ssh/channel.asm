; =============================================================================
; channel.asm — SSH Channel Management (RFC 4254)
;
; Single channel only. Handles:
;   CHANNEL_OPEN("session")     -> CHANNEL_OPEN_CONFIRMATION
;   CHANNEL_REQUEST("pty-req")  -> handled by pty.asm
;   CHANNEL_REQUEST("shell")    -> start shell
;   CHANNEL_DATA                -> forward to PTY
;   CHANNEL_WINDOW_ADJUST       -> update remote window
;   CHANNEL_EOF/CLOSE           -> cleanup
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
    session_str:     db "session"
    session_str_len  equ $ - session_str

    pty_req_str:     db "pty-req"
    pty_req_str_len  equ $ - pty_req_str

    shell_str:       db "shell"
    shell_str_len    equ $ - shell_str

    env_str:         db "env"
    env_str_len      equ $ - env_str

    exec_str:        db "exec"
    exec_str_len     equ $ - exec_str

    winsz_str:       db "window-change"
    winsz_str_len    equ $ - winsz_str

    msg_chan_open:    db "Channel open request", 0
    msg_chan_data:    db "Channel data received", 0
    msg_chan_eof:     db "Channel EOF", 0
    msg_chan_close:   db "Channel close", 0
    msg_chan_req:     db "Channel request", 0
    msg_chan_pty:     db "PTY request", 0
    msg_chan_shell:   db "Shell request", 0
    msg_chan_confirm: db "Channel open confirmed", 0
    msg_chan_winsz:   db "Window size change", 0

section .bss
    global chan_payload_buf
    chan_payload_buf: resb 4096
    chan_recv_buf:    resb 4096

section .text

extern _ssh_packet_send
extern _ssh_packet_recv
extern _read_be32
extern _write_be32
extern _ssh_write_string
extern _memcmp
extern _memcpy
extern _log_str
extern _pty_open
extern _pty_set_winsize
extern _shell_spawn
extern _sys_write

; ssh_channel_open(session) -> 0 or -1
; Wait for and handle CHANNEL_OPEN
; rdi = session pointer
global _ssh_channel_open
_ssh_channel_open:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session

.wait_channel_open:
    mov rdi, r12
    lea rsi, [rbp - 1]
    lea rdx, [chan_recv_buf]
    lea rcx, [rbp - 8]
    call _ssh_packet_recv
    test eax, eax
    jnz .chan_fail

    movzx eax, byte [rbp - 1]

    ; Skip IGNORE/DEBUG/UNIMPLEMENTED
    cmp al, SSH_MSG_IGNORE
    je .wait_channel_open
    cmp al, SSH_MSG_DEBUG
    je .wait_channel_open
    cmp al, SSH_MSG_UNIMPLEMENTED
    je .wait_channel_open

    ; Handle GLOBAL_REQUEST (just reject)
    cmp al, SSH_MSG_GLOBAL_REQUEST
    jne .not_global_req
    ; Send REQUEST_FAILURE
    mov rdi, r12
    mov esi, SSH_MSG_REQUEST_FAILURE
    xor edx, edx
    xor ecx, ecx
    call _ssh_packet_send
    jmp .wait_channel_open

.not_global_req:
    cmp al, SSH_MSG_CHANNEL_OPEN
    jne .chan_fail

    lea rdi, [rel msg_chan_open]
    call _log_str

    ; Parse CHANNEL_OPEN:
    ; SSH string channel_type
    ; uint32 sender_channel
    ; uint32 initial_window_size
    ; uint32 maximum_packet_size
    lea r14, [chan_recv_buf]

    ; Channel type
    lea rdi, [r14]
    call _read_be32
    mov ebx, eax             ; type string length

    ; Verify "session"
    cmp ebx, session_str_len
    jne .chan_open_fail

    lea rdi, [r14 + 4]
    lea rsi, [session_str]
    mov edx, session_str_len
    call _memcmp
    test eax, eax
    jnz .chan_open_fail

    ; Parse sender channel, window, max packet
    lea eax, [ebx + 4]      ; skip type string
    lea rdi, [r14 + rax]
    call _read_be32
    mov r13d, eax            ; remote channel ID
    add rdi, 4
    call _read_be32
    mov r15d, eax            ; remote window size
    add rdi, 4
    call _read_be32
    mov ebx, eax             ; remote max packet

    ; Set up channel in session
    ; Use channel 0 (single channel)
    lea rdi, [r12 + SESS_CHANNELS]
    mov dword [rdi + CHAN_ACTIVE], 1
    mov dword [rdi + CHAN_LOCAL_ID], 0
    mov [rdi + CHAN_REMOTE_ID], r13d
    mov dword [rdi + CHAN_LOCAL_WINDOW], SSH_CHANNEL_WINDOW_SIZE
    mov [rdi + CHAN_REMOTE_WINDOW], r15d
    mov dword [rdi + CHAN_LOCAL_MAX_PACKET], SSH_CHANNEL_MAX_PACKET
    mov [rdi + CHAN_REMOTE_MAX_PACKET], ebx
    mov dword [rdi + CHAN_STATE], 1       ; open
    mov dword [rdi + CHAN_PTY_MASTER], -1
    mov dword [rdi + CHAN_PTY_SLAVE], -1
    mov dword [rdi + CHAN_CHILD_PID], 0

    ; Send CHANNEL_OPEN_CONFIRMATION
    ; uint32 recipient_channel (remote_id)
    ; uint32 sender_channel (local_id = 0)
    ; uint32 initial_window_size
    ; uint32 maximum_packet_size
    lea rdi, [chan_payload_buf]
    mov esi, r13d
    bswap esi
    mov [rdi], esi           ; recipient = remote_id
    mov dword [rdi + 4], 0   ; sender = 0 (BE, already 0)
    mov eax, SSH_CHANNEL_WINDOW_SIZE
    bswap eax
    mov [rdi + 8], eax       ; window
    mov eax, SSH_CHANNEL_MAX_PACKET
    bswap eax
    mov [rdi + 12], eax      ; max packet

    lea rdi, [rel msg_chan_confirm]
    call _log_str

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_OPEN_CONFIRMATION
    lea rdx, [chan_payload_buf]
    mov ecx, 16
    call _ssh_packet_send
    test eax, eax
    jnz .chan_fail

    xor eax, eax
    jmp .chan_done

.chan_open_fail:
    ; Send CHANNEL_OPEN_FAILURE
    lea rdi, [chan_payload_buf]
    mov esi, r13d
    bswap esi
    mov [rdi], esi           ; recipient channel
    mov dword [rdi + 4], 0   ; reason: administratively prohibited (BE)
    mov eax, 1
    bswap eax
    mov [rdi + 4], eax
    mov dword [rdi + 8], 0   ; description length
    mov dword [rdi + 12], 0  ; language length

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_OPEN_FAILURE
    lea rdx, [chan_payload_buf]
    mov ecx, 16
    call _ssh_packet_send

.chan_fail:
    mov eax, -1

.chan_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 64
    pop rbp
    ret

; ssh_channel_handle_request(session, payload, payload_len) -> action code
; Parse and handle CHANNEL_REQUEST
; Returns: 0 = handled, 1 = shell requested, -1 = error
; rdi = session, rsi = payload, edx = payload_len
global _ssh_channel_handle_request
_ssh_channel_handle_request:
    push rbp
    mov rbp, rsp
    sub rsp, 64
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session
    mov r14, rsi            ; payload
    mov r15d, edx           ; payload_len

    ; Parse:
    ; uint32 recipient_channel
    ; SSH string request_type
    ; boolean want_reply
    ; [type-specific data]

    lea rdi, [r14]
    call _read_be32          ; recipient channel (should be 0)
    ; Skip it
    add r14, 4

    lea rdi, [r14]
    call _read_be32
    mov ebx, eax             ; request type string length
    lea r13, [r14 + 4]       ; request type string

    lea eax, [ebx + 4]
    add r14, rax             ; advance past request type

    ; want_reply
    movzx ecx, byte [r14]
    mov [rbp - 1], cl        ; save want_reply
    inc r14

    ; Check request type
    ; --- pty-req ---
    cmp ebx, pty_req_str_len
    jne .not_pty_req

    lea rdi, [r13]
    lea rsi, [pty_req_str]
    mov edx, pty_req_str_len
    call _memcmp
    test eax, eax
    jnz .not_pty_req

    lea rdi, [rel msg_chan_pty]
    call _log_str

    ; Parse pty-req specific data:
    ; SSH string TERM env var
    ; uint32 terminal width (chars)
    ; uint32 terminal height (rows)
    ; uint32 terminal width (pixels)
    ; uint32 terminal height (pixels)
    ; SSH string terminal modes

    ; Skip TERM string
    lea rdi, [r14]
    call _read_be32
    lea eax, [eax + 4]
    add r14, rax

    ; Read dimensions
    lea rdi, [r14]
    call _read_be32
    mov r13d, eax            ; cols
    lea rdi, [r14 + 4]
    call _read_be32
    mov ebx, eax             ; rows

    ; Store in channel
    lea rdi, [r12 + SESS_CHANNELS]
    mov [rdi + CHAN_TERM_COLS], r13d
    mov [rdi + CHAN_TERM_ROWS], ebx

    ; Open PTY
    lea rdi, [r12 + SESS_CHANNELS]
    call _pty_open
    test eax, eax
    jnz .req_fail

    ; Set window size
    lea rdi, [r12 + SESS_CHANNELS]
    call _pty_set_winsize

    ; Send success reply if want_reply
    cmp byte [rbp - 1], 0
    je .req_success_no_reply

    ; Send CHANNEL_SUCCESS
    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_SUCCESS
    lea rdx, [chan_payload_buf]
    mov ecx, 4
    call _ssh_packet_send

.req_success_no_reply:
    xor eax, eax
    jmp .req_done

.not_pty_req:
    ; --- shell ---
    cmp ebx, shell_str_len
    jne .not_shell

    lea rdi, [r13]
    lea rsi, [shell_str]
    mov edx, shell_str_len
    call _memcmp
    test eax, eax
    jnz .not_shell

    lea rdi, [rel msg_chan_shell]
    call _log_str

    ; Send success reply if want_reply
    cmp byte [rbp - 1], 0
    je .shell_no_reply

    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_SUCCESS
    lea rdx, [chan_payload_buf]
    mov ecx, 4
    call _ssh_packet_send

.shell_no_reply:
    mov eax, 1               ; shell requested
    jmp .req_done

.not_shell:
    ; --- window-change ---
    cmp ebx, winsz_str_len
    jne .not_winsz

    lea rdi, [r13]
    lea rsi, [winsz_str]
    mov edx, winsz_str_len
    call _memcmp
    test eax, eax
    jnz .not_winsz

    lea rdi, [rel msg_chan_winsz]
    call _log_str

    ; Parse: uint32 cols, uint32 rows, uint32 xpixel, uint32 ypixel
    lea rdi, [r14]
    call _read_be32
    mov r13d, eax            ; cols
    lea rdi, [r14 + 4]
    call _read_be32
    ; eax = rows

    lea rdi, [r12 + SESS_CHANNELS]
    mov [rdi + CHAN_TERM_COLS], r13d
    mov [rdi + CHAN_TERM_ROWS], eax

    call _pty_set_winsize

    xor eax, eax
    jmp .req_done

.not_winsz:
    ; --- env (ignore) ---
    ; --- exec (ignore) ---
    ; Unknown request: send failure if want_reply
    cmp byte [rbp - 1], 0
    je .req_ignore

    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_FAILURE
    lea rdx, [chan_payload_buf]
    mov ecx, 4
    call _ssh_packet_send

.req_ignore:
    xor eax, eax
    jmp .req_done

.req_fail:
    mov eax, -1

.req_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 64
    pop rbp
    ret

; ssh_channel_send_data(session, data, len) -> 0 or -1
; Send CHANNEL_DATA to the client
; rdi = session, rsi = data, edx = length
global _ssh_channel_send_data
_ssh_channel_send_data:
    push rbp
    mov rbp, rsp
    sub rsp, 32
    push rbx
    push r12
    push r13

    mov r12, rdi            ; session
    mov r13, rsi            ; data
    mov ebx, edx            ; length

    ; Check remote window
    lea rdi, [r12 + SESS_CHANNELS]
    mov eax, [rdi + CHAN_REMOTE_WINDOW]
    test eax, eax
    jz .send_data_done       ; no window space, drop

    ; Clamp to remote window and max packet
    cmp ebx, eax
    cmova ebx, eax
    mov eax, [rdi + CHAN_REMOTE_MAX_PACKET]
    cmp ebx, eax
    cmova ebx, eax

    ; Build CHANNEL_DATA payload:
    ; uint32 recipient_channel
    ; SSH string data
    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax           ; recipient channel

    ; Data as SSH string
    mov eax, ebx
    bswap eax
    mov [rdi + 4], eax       ; data length

    ; Copy data
    lea rdi, [chan_payload_buf + 8]
    mov rsi, r13
    mov ecx, ebx
    rep movsb

    ; Total payload = 4 + 4 + data_len
    lea ecx, [ebx + 8]

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_DATA
    lea rdx, [chan_payload_buf]
    ; ecx already set
    call _ssh_packet_send
    test eax, eax
    jnz .send_data_fail

    ; Decrease remote window
    lea rdi, [r12 + SESS_CHANNELS]
    sub [rdi + CHAN_REMOTE_WINDOW], ebx

.send_data_done:
    xor eax, eax
    jmp .send_data_ret

.send_data_fail:
    mov eax, -1

.send_data_ret:
    pop r13
    pop r12
    pop rbx
    add rsp, 32
    pop rbp
    ret

; ssh_channel_send_eof(session)
; Send CHANNEL_EOF
global _ssh_channel_send_eof
_ssh_channel_send_eof:
    push rbx
    push r12
    mov r12, rdi

    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_EOF
    lea rdx, [chan_payload_buf]
    mov ecx, 4
    call _ssh_packet_send

    pop r12
    pop rbx
    ret

; ssh_channel_send_close(session)
; Send CHANNEL_CLOSE
global _ssh_channel_send_close
_ssh_channel_send_close:
    push rbx
    push r12
    mov r12, rdi

    lea rdi, [chan_payload_buf]
    lea rsi, [r12 + SESS_CHANNELS]
    mov eax, [rsi + CHAN_REMOTE_ID]
    bswap eax
    mov [rdi], eax

    mov rdi, r12
    mov esi, SSH_MSG_CHANNEL_CLOSE
    lea rdx, [chan_payload_buf]
    mov ecx, 4
    call _ssh_packet_send

    ; Mark channel closed
    lea rdi, [r12 + SESS_CHANNELS]
    mov dword [rdi + CHAN_STATE], 4

    pop r12
    pop rbx
    ret
