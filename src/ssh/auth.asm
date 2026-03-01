; =============================================================================
; auth.asm — SSH User Authentication (RFC 4252)
;
; Minimal implementation: accept any password.
;
; Flow:
;   1. Receive SERVICE_REQUEST("ssh-userauth")
;   2. Send SERVICE_ACCEPT("ssh-userauth")
;   3. Receive USERAUTH_REQUEST with method="none"
;   4. Reply USERAUTH_FAILURE("password", partial=false)
;   5. Receive USERAUTH_REQUEST with method="password"
;   6. Reply USERAUTH_SUCCESS
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
    ; Service name
    ssh_userauth_str: db "ssh-userauth"
    ssh_userauth_len equ $ - ssh_userauth_str

    ssh_connection_str: db "ssh-connection"
    ssh_connection_len equ $ - ssh_connection_str

    ; Auth method names
    auth_password_str: db "password"
    auth_password_len equ $ - auth_password_str

    auth_none_str: db "none"
    auth_none_len equ $ - auth_none_str

    msg_auth_start:    db "Starting user authentication", 0
    msg_svc_request:   db "Received SERVICE_REQUEST", 0
    msg_svc_accept:    db "Sending SERVICE_ACCEPT", 0
    msg_auth_none:     db "Auth method: none, sending failure", 0
    msg_auth_password: db "Auth method: password, accepting", 0
    msg_auth_success:  db "Authentication successful", 0
    msg_auth_fail:     db "Authentication failed", 0
    msg_auth_user:     db "User: ", 0

section .bss
    auth_payload_buf: resb 1024
    auth_recv_buf:    resb 4096

section .text

extern _ssh_packet_send
extern _ssh_packet_recv
extern _read_be32
extern _write_be32
extern _ssh_write_string
extern _ssh_read_string
extern _memcmp
extern _memcpy
extern _log_str
extern _log_msg

; ssh_auth(session) -> 0 success, -1 failure
; Handle the authentication phase
; rdi = session pointer
global _ssh_auth
_ssh_auth:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session

    lea rdi, [rel msg_auth_start]
    call _log_str

    ; --- Step 1: Receive SERVICE_REQUEST ---
.wait_service_request:
    mov rdi, r12
    lea rsi, [rbp - 1]          ; out_type
    lea rdx, [auth_recv_buf]     ; out_payload
    lea rcx, [rbp - 8]          ; out_len
    call _ssh_packet_recv
    test eax, eax
    jnz .auth_fail

    movzx eax, byte [rbp - 1]

    ; Handle SSH_MSG_IGNORE/DEBUG/UNIMPLEMENTED by discarding
    cmp al, SSH_MSG_IGNORE
    je .wait_service_request
    cmp al, SSH_MSG_DEBUG
    je .wait_service_request
    cmp al, SSH_MSG_UNIMPLEMENTED
    je .wait_service_request

    cmp al, SSH_MSG_SERVICE_REQUEST
    jne .auth_fail

    lea rdi, [rel msg_svc_request]
    call _log_str

    ; Parse service name from payload
    ; Payload: SSH string <service_name>
    lea rdi, [auth_recv_buf]
    call _read_be32          ; string length
    mov ebx, eax             ; service name length

    ; Verify it's "ssh-userauth" (or "ssh-connection")
    ; We'll accept "ssh-userauth" only
    cmp ebx, ssh_userauth_len
    jne .auth_fail

    lea rdi, [auth_recv_buf + 4]
    lea rsi, [ssh_userauth_str]
    mov edx, ebx
    call _memcmp
    test eax, eax
    jnz .auth_fail

    ; --- Step 2: Send SERVICE_ACCEPT ---
    lea rdi, [rel msg_svc_accept]
    call _log_str

    ; Build payload: SSH string "ssh-userauth"
    lea rdi, [auth_payload_buf]
    lea rsi, [ssh_userauth_str]
    mov edx, ssh_userauth_len
    call _ssh_write_string
    mov ebx, eax             ; payload length

    mov rdi, r12
    mov esi, SSH_MSG_SERVICE_ACCEPT
    lea rdx, [auth_payload_buf]
    mov ecx, ebx
    call _ssh_packet_send
    test eax, eax
    jnz .auth_fail

    ; --- Step 3-6: Handle USERAUTH_REQUEST(s) ---
    mov r13d, 0              ; attempt counter

.auth_loop:
    inc r13d
    cmp r13d, SSH_MAX_AUTH_ATTEMPTS
    ja .auth_fail

    ; Receive USERAUTH_REQUEST
    mov rdi, r12
    lea rsi, [rbp - 1]
    lea rdx, [auth_recv_buf]
    lea rcx, [rbp - 8]
    call _ssh_packet_recv
    test eax, eax
    jnz .auth_fail

    movzx eax, byte [rbp - 1]

    ; Skip IGNORE/DEBUG
    cmp al, SSH_MSG_IGNORE
    je .auth_loop
    cmp al, SSH_MSG_DEBUG
    je .auth_loop

    cmp al, SSH_MSG_USERAUTH_REQUEST
    jne .auth_fail

    ; Parse USERAUTH_REQUEST payload:
    ; SSH string user_name
    ; SSH string service_name ("ssh-connection")
    ; SSH string method_name ("none" or "password")
    ; [method-specific fields]

    lea r14, [auth_recv_buf]
    xor r15d, r15d           ; offset

    ; Read username
    lea rdi, [r14]
    call _read_be32
    mov ebx, eax             ; username length

    ; Copy username to session (truncate to 63 bytes)
    cmp ebx, 63
    jbe .user_ok
    mov ebx, 63
.user_ok:
    lea rdi, [r12 + SESS_AUTH_USER]
    lea rsi, [r14 + 4]
    mov ecx, ebx
    rep movsb
    mov byte [r12 + SESS_AUTH_USER + rbx], 0  ; null terminate
    mov [r12 + SESS_AUTH_USER_LEN], ebx

    ; Log username
    lea rdi, [rel msg_auth_user]
    call _log_str
    lea rdi, [r12 + SESS_AUTH_USER]
    mov esi, [r12 + SESS_AUTH_USER_LEN]
    call _log_msg

    ; Advance past username string
    lea eax, [ebx + 4]
    add r15d, eax

    ; Skip service name string
    lea rdi, [r14 + r15]
    call _read_be32
    lea eax, [eax + 4]
    add r15d, eax

    ; Read method name
    lea rdi, [r14 + r15]
    call _read_be32
    mov ebx, eax             ; method name length
    lea r14, [r14 + r15 + 4] ; pointer to method name string

    ; Check method name
    ; Is it "none"?
    cmp ebx, auth_none_len
    jne .check_password

    lea rdi, [r14]
    lea rsi, [auth_none_str]
    mov edx, auth_none_len
    call _memcmp
    test eax, eax
    jnz .check_password

    ; Method = "none" -> send USERAUTH_FAILURE
    lea rdi, [rel msg_auth_none]
    call _log_str

    ; Build FAILURE payload: name-list "password" + partial_success=false
    lea rdi, [auth_payload_buf]
    lea rsi, [auth_password_str]
    mov edx, auth_password_len
    call _ssh_write_string
    mov ebx, eax

    ; partial_success = false (0)
    lea rdi, [auth_payload_buf]
    add rdi, rbx
    mov byte [rdi], 0
    inc ebx

    mov rdi, r12
    mov esi, SSH_MSG_USERAUTH_FAILURE
    lea rdx, [auth_payload_buf]
    mov ecx, ebx
    call _ssh_packet_send
    test eax, eax
    jnz .auth_fail

    jmp .auth_loop

.check_password:
    cmp ebx, auth_password_len
    jne .auth_method_unknown

    lea rdi, [r14]
    lea rsi, [auth_password_str]
    mov edx, auth_password_len
    call _memcmp
    test eax, eax
    jnz .auth_method_unknown

    ; Method = "password" -> accept any password
    lea rdi, [rel msg_auth_password]
    call _log_str

    ; Send USERAUTH_SUCCESS (no payload)
    mov rdi, r12
    mov esi, SSH_MSG_USERAUTH_SUCCESS
    xor edx, edx
    xor ecx, ecx
    call _ssh_packet_send
    test eax, eax
    jnz .auth_fail

    lea rdi, [rel msg_auth_success]
    call _log_str

    ; Set session state to authenticated
    mov dword [r12 + SESS_STATE], 3     ; connected

    xor eax, eax
    jmp .auth_done

.auth_method_unknown:
    ; Unknown method -> send FAILURE with "password"
    lea rdi, [auth_payload_buf]
    lea rsi, [auth_password_str]
    mov edx, auth_password_len
    call _ssh_write_string
    mov ebx, eax
    lea rdi, [auth_payload_buf]
    add rdi, rbx
    mov byte [rdi], 0
    inc ebx

    mov rdi, r12
    mov esi, SSH_MSG_USERAUTH_FAILURE
    lea rdx, [auth_payload_buf]
    mov ecx, ebx
    call _ssh_packet_send
    test eax, eax
    jnz .auth_fail

    jmp .auth_loop

.auth_fail:
    lea rdi, [rel msg_auth_fail]
    call _log_str
    mov eax, -1

.auth_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret
