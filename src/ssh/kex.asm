; =============================================================================
; kex.asm — SSH Key Exchange (RFC 4253 + RFC 8731)
;
; Single algorithm per slot:
;   kex:        curve25519-sha256
;   host key:   ssh-ed25519
;   cipher:     chacha20-poly1305@openssh.com
;   mac:        none (implicit in AEAD)
;   compress:   none
;
; Flow:
;   1. Send our KEXINIT
;   2. Receive client KEXINIT (save raw bytes for hash)
;   3. Receive KEX_ECDH_INIT (client's X25519 pubkey Q_C)
;   4. Generate ephemeral keypair (q_s, Q_S)
;   5. Compute shared secret K = x25519(q_s, Q_C)
;   6. Compute exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
;   7. Sign H with Ed25519 host key
;   8. Send KEX_ECDH_REPLY (K_S, Q_S, signature)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data

; Algorithm name-list strings (hardcoded single algorithms)
kex_algorithms:     db "curve25519-sha256"
kex_algorithms_len  equ $ - kex_algorithms

host_key_algorithms: db "ssh-ed25519"
host_key_alg_len    equ $ - host_key_algorithms

cipher_algorithms:  db "chacha20-poly1305@openssh.com"
cipher_alg_len      equ $ - cipher_algorithms

mac_algorithms:     db "none"
mac_alg_len         equ $ - mac_algorithms

comp_algorithms:    db "none"
comp_alg_len        equ $ - comp_algorithms

; SSH string: "ssh-ed25519"
ssh_ed25519_str:    db "ssh-ed25519"
ssh_ed25519_len     equ $ - ssh_ed25519_str

; SSH string: "curve25519-sha256"
curve25519_sha256_str: db "curve25519-sha256"
curve25519_sha256_len  equ $ - curve25519_sha256_str

msg_kex_start:    db "Starting key exchange", 0
msg_kex_send:     db "Sending KEXINIT", 0
msg_kex_sent_ok:  db "KEXINIT sent OK", 0
msg_kex_recv:     db "Received client KEXINIT", 0
msg_kex_ecdh:     db "Received KEX_ECDH_INIT", 0
msg_kex_reply:    db "Sending KEX_ECDH_REPLY", 0
msg_kex_done:     db "Key exchange complete", 0
msg_kex_fail:     db "Key exchange failed", 0
msg_kex_recv_wait: db "Waiting for client KEXINIT", 0
msg_kex_recv_fail: db "Recv client KEXINIT failed", 0
msg_kex_type_bad:  db "Wrong packet type (expected KEXINIT)", 0
msg_dbg_hashlen:   db "Hash input len: ", 0
msg_dbg_hash:      db "H: ", 0
msg_dbg_pubkey:    db "PK: ", 0
msg_dbg_sig:       db "SIG: ", 0
msg_dbg_ks:        db "K_S: ", 0
msg_dbg_hash_in:   db "HASH_IN: ", 0
msg_dbg_qc:        db "Q_C: ", 0
msg_dbg_qs:        db "Q_S: ", 0
msg_dbg_shared:    db "K_raw: ", 0
msg_dbg_mpint:     db "K_mpint: ", 0
msg_dbg_is_len:    db "I_S_LEN: ", 0
msg_dbg_is_data:   db "I_S_DATA: ", 0
msg_dbg_ptr_expected: db "khb_addr: ", 0
msg_dbg_ptr_actual:   db "is_ptr: ", 0
msg_dbg_reply:        db "REPLY: ", 0
msg_dbg_reply_len:    db "REPLY_LEN: ", 0

section .bss
    ; Buffers for key exchange
    kex_payload_buf: resb 2048   ; for building KEXINIT payload
    kex_hash_buf:    resb 8192   ; for building exchange hash input
    kex_temp:        resb 256    ; misc temp

section .text

extern _ssh_packet_send
extern _ssh_packet_recv
extern _random_bytes
extern _memcpy
extern _memset
extern _write_be32
extern _read_be32
extern _ssh_write_string
extern _x25519
extern _x25519_basepoint
extern _ed25519_sign
extern _ed25519_publickey
extern _sha256_hash
extern _log_str
extern _log_msg
extern _log_hex

; _build_kexinit_payload(buf) -> payload length
; Build KEXINIT payload (everything after the type byte)
; rdi = output buffer
; Returns length in eax
_build_kexinit_payload:
    push rbp
    mov rbp, rsp
    push rbx
    push r12

    mov r12, rdi            ; output buffer
    xor ebx, ebx            ; offset

    ; 16 bytes random cookie
    mov rdi, r12
    mov rsi, 16
    call _random_bytes
    add ebx, 16

    ; 10 name-lists (each as SSH string: 4-byte len + data)
    ; 1. kex_algorithms
    lea rdi, [r12 + rbx]
    lea rsi, [kex_algorithms]
    mov edx, kex_algorithms_len
    call _ssh_write_string
    add ebx, eax

    ; 2. server_host_key_algorithms
    lea rdi, [r12 + rbx]
    lea rsi, [host_key_algorithms]
    mov edx, host_key_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 3. encryption_algorithms_client_to_server
    lea rdi, [r12 + rbx]
    lea rsi, [cipher_algorithms]
    mov edx, cipher_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 4. encryption_algorithms_server_to_client
    lea rdi, [r12 + rbx]
    lea rsi, [cipher_algorithms]
    mov edx, cipher_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 5. mac_algorithms_client_to_server
    lea rdi, [r12 + rbx]
    lea rsi, [mac_algorithms]
    mov edx, mac_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 6. mac_algorithms_server_to_client
    lea rdi, [r12 + rbx]
    lea rsi, [mac_algorithms]
    mov edx, mac_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 7. compression_algorithms_client_to_server
    lea rdi, [r12 + rbx]
    lea rsi, [comp_algorithms]
    mov edx, comp_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 8. compression_algorithms_server_to_client
    lea rdi, [r12 + rbx]
    lea rsi, [comp_algorithms]
    mov edx, comp_alg_len
    call _ssh_write_string
    add ebx, eax

    ; 9. languages_client_to_server (empty)
    lea rdi, [r12 + rbx]
    mov dword [rdi], 0      ; empty string
    add ebx, 4

    ; 10. languages_server_to_client (empty)
    lea rdi, [r12 + rbx]
    mov dword [rdi], 0
    add ebx, 4

    ; first_kex_packet_follows = FALSE
    mov byte [r12 + rbx], 0
    inc ebx

    ; reserved uint32 = 0
    mov dword [r12 + rbx], 0
    add ebx, 4

    mov eax, ebx
    pop r12
    pop rbx
    pop rbp
    ret

; ssh_kex_exchange(session) -> 0 success, -1 failure
; Performs the entire key exchange sequence
; rdi = session pointer
global _ssh_kex_exchange
_ssh_kex_exchange:
    push rbp
    mov rbp, rsp
    sub rsp, 512
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session

    lea rdi, [rel msg_kex_start]
    call _log_str

    ; --- Step 1: Send our KEXINIT ---
    lea rdi, [rel msg_kex_send]
    call _log_str

    lea rdi, [kex_payload_buf]
    call _build_kexinit_payload
    mov r13d, eax            ; kexinit payload length

    ; Save our KEXINIT payload (type byte + payload) for exchange hash
    ; We need: type(20) + payload
    mov eax, r13d
    inc eax                  ; +1 for type byte
    mov [r12 + SESS_SERVER_KEXINIT_LEN], eax

    ; Allocate and copy
    lea rdi, [kex_hash_buf]
    mov byte [rdi], SSH_MSG_KEXINIT
    lea rsi, [kex_payload_buf]
    lea rdi, [kex_hash_buf + 1]
    mov ecx, r13d
    rep movsb
    ; Store pointer
    lea rax, [kex_hash_buf]
    mov [r12 + SESS_SERVER_KEXINIT], rax

    ; Send KEXINIT packet
    mov rdi, r12
    mov esi, SSH_MSG_KEXINIT
    lea rdx, [kex_payload_buf]
    mov ecx, r13d
    call _ssh_packet_send
    test eax, eax
    jnz .kex_fail

    lea rdi, [rel msg_kex_sent_ok]
    call _log_str

    ; --- Step 2: Receive client KEXINIT ---
    lea rdi, [rel msg_kex_recv_wait]
    call _log_str

    ; Use kex_temp for type, kex_payload_buf for payload
    mov rdi, r12
    lea rsi, [rbp - 1]              ; out_type
    lea rdx, [kex_payload_buf]       ; out_payload
    lea rcx, [rbp - 8]              ; out_len
    call _ssh_packet_recv
    test eax, eax
    jnz .kex_recv_fail

    ; Verify type
    cmp byte [rbp - 1], SSH_MSG_KEXINIT
    jne .kex_type_fail

    lea rdi, [rel msg_kex_recv]
    call _log_str

    ; Save client KEXINIT (type + payload) for exchange hash
    mov eax, [rbp - 8]
    inc eax                  ; +1 for type byte
    mov [r12 + SESS_CLIENT_KEXINIT_LEN], eax

    ; Copy: type byte + payload data to kex_hash_buf+4096
    lea rdi, [kex_hash_buf + 4096]
    mov byte [rdi], SSH_MSG_KEXINIT
    lea rdi, [kex_hash_buf + 4097]
    lea rsi, [kex_payload_buf]
    mov ecx, [rbp - 8]
    rep movsb
    lea rax, [kex_hash_buf + 4096]
    mov [r12 + SESS_CLIENT_KEXINIT], rax

    ; --- Step 3: Receive KEX_ECDH_INIT ---
    mov rdi, r12
    lea rsi, [rbp - 1]
    lea rdx, [kex_payload_buf]
    lea rcx, [rbp - 8]
    call _ssh_packet_recv
    test eax, eax
    jnz .kex_fail

    cmp byte [rbp - 1], SSH_MSG_KEX_ECDH_INIT
    jne .kex_fail

    lea rdi, [rel msg_kex_ecdh]
    call _log_str

    ; Parse client's X25519 public key Q_C from payload
    ; Payload: SSH string [uint32 len][32-byte key]
    lea rdi, [kex_payload_buf]
    call _read_be32          ; string length
    cmp eax, 32
    jne .kex_fail

    ; Q_C is at kex_payload_buf + 4 (32 bytes)
    ; Save it on stack
    %define QC rbp - 48      ; 32 bytes (uses rbp-48 to rbp-17)

    lea rdi, [QC]
    lea rsi, [kex_payload_buf + 4]
    mov ecx, 32
    rep movsb

    ; --- Step 4: Generate ephemeral X25519 keypair ---
    %define QS_PRIV rbp - 80  ; 32 bytes (ephemeral private)
    %define QS_PUB  rbp - 112 ; 32 bytes (ephemeral public Q_S)
    %define SHARED  rbp - 144 ; 32 bytes (shared secret K)

    ; Generate random private key
    lea rdi, [QS_PRIV]
    mov rsi, 32
    call _random_bytes

    ; Compute Q_S = scalar * basepoint
    lea rdi, [QS_PUB]
    lea rsi, [QS_PRIV]
    call _x25519_basepoint

    ; --- Step 5: Compute shared secret K = x25519(q_s, Q_C) ---
    lea rdi, [SHARED]
    lea rsi, [QS_PRIV]
    lea rdx, [QC]
    call _x25519

    ; Store shared secret in session
    lea rdi, [r12 + SESS_KEX_SHARED_SECRET]
    lea rsi, [SHARED]
    mov ecx, 32
    rep movsb

    ; Debug: dump Q_C, Q_S, shared secret
    lea rdi, [rel msg_dbg_qc]
    lea rsi, [QC]
    mov edx, 32
    call _log_hex

    lea rdi, [rel msg_dbg_qs]
    lea rsi, [QS_PUB]
    mov edx, 32
    call _log_hex

    lea rdi, [rel msg_dbg_shared]
    lea rsi, [SHARED]
    mov edx, 32
    call _log_hex

    ; --- Step 6: Compute exchange hash H ---
    ; H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
    ; All items are SSH strings (4-byte length prefix)
    ; V_C, V_S = version strings (without \r\n)
    ; I_C, I_S = KEXINIT payloads (type byte + content)
    ; K_S = host public key blob
    ; Q_C, Q_S = ECDH public keys (as SSH strings)
    ; K = shared secret as mpint

    ; First, generate host key if not already done
    ; Check if host key is initialized (pubkey non-zero)
    mov rax, [r12 + SESS_HOST_KEY_PUB]
    or rax, [r12 + SESS_HOST_KEY_PUB + 8]
    or rax, [r12 + SESS_HOST_KEY_PUB + 16]
    or rax, [r12 + SESS_HOST_KEY_PUB + 24]
    test rax, rax
    jnz .host_key_ready

    ; Generate host key: random seed -> Ed25519 keypair
    lea rdi, [r12 + SESS_HOST_KEY_PRIV]
    mov rsi, 32
    call _random_bytes

    lea rdi, [r12 + SESS_HOST_KEY_PRIV]
    lea rsi, [r12 + SESS_HOST_KEY_PUB]
    call _ed25519_publickey

.host_key_ready:
    ; Build host key blob K_S: SSH string "ssh-ed25519" + SSH string <32-byte pubkey>
    ; Total: 4 + 11 + 4 + 32 = 51 bytes
    %define KS_BLOB rbp - 208  ; 64 bytes for host key blob
    %define KS_BLOB_LEN 51

    lea rdi, [KS_BLOB]
    lea rsi, [ssh_ed25519_str]
    mov edx, ssh_ed25519_len
    call _ssh_write_string
    mov ebx, eax

    lea rdi, [KS_BLOB]
    add rdi, rbx
    lea rsi, [r12 + SESS_HOST_KEY_PUB]
    mov edx, 32
    call _ssh_write_string
    add ebx, eax            ; ebx = total K_S blob length

    ; Now build the hash input in kex_hash_buf at offset 2048
    ; (I_S is stored at offset 0..~200, I_C at 4096+, so 2048 is safe)
    ; Format: each field as SSH string
    lea r14, [kex_hash_buf + 2048]
    xor r15d, r15d          ; offset

    ; V_C (client version string)
    lea rdi, [r14 + r15]
    lea rsi, [r12 + SESS_CLIENT_VERSION]
    mov edx, [r12 + SESS_CLIENT_VERSION_LEN]
    call _ssh_write_string
    add r15d, eax

    ; V_S (server version string)
    lea rdi, [r14 + r15]
    lea rsi, [r12 + SESS_SERVER_VERSION]
    mov edx, [r12 + SESS_SERVER_VERSION_LEN]
    call _ssh_write_string
    add r15d, eax

    ; I_C (client KEXINIT raw)
    lea rdi, [r14 + r15]
    mov rsi, [r12 + SESS_CLIENT_KEXINIT]
    mov edx, [r12 + SESS_CLIENT_KEXINIT_LEN]
    call _ssh_write_string
    add r15d, eax

    ; Debug: dump I_S len and first 20 bytes before writing
    ; Store SESS_SERVER_KEXINIT_LEN as 4 BE bytes for logging
    mov eax, [r12 + SESS_SERVER_KEXINIT_LEN]
    bswap eax
    mov [rbp - 260], eax
    lea rdi, [rel msg_dbg_is_len]
    lea rsi, [rbp - 260]
    mov edx, 4
    call _log_hex

    ; Dump first 20 bytes of I_S data
    lea rdi, [rel msg_dbg_is_data]
    mov rsi, [r12 + SESS_SERVER_KEXINIT]
    mov edx, 20
    call _log_hex

    ; Also dump kex_hash_buf address vs stored pointer
    ; Store both as 8-byte values
    lea rax, [kex_hash_buf]
    mov [rbp - 268], rax
    mov rax, [r12 + SESS_SERVER_KEXINIT]
    mov [rbp - 276], rax
    lea rdi, [rel msg_dbg_ptr_expected]
    lea rsi, [rbp - 268]
    mov edx, 8
    call _log_hex
    lea rdi, [rel msg_dbg_ptr_actual]
    lea rsi, [rbp - 276]
    mov edx, 8
    call _log_hex

    ; I_S (server KEXINIT raw)
    lea rdi, [r14 + r15]
    mov rsi, [r12 + SESS_SERVER_KEXINIT]
    mov edx, [r12 + SESS_SERVER_KEXINIT_LEN]
    call _ssh_write_string
    add r15d, eax

    ; K_S (host key blob)
    lea rdi, [r14 + r15]
    lea rsi, [KS_BLOB]
    mov edx, ebx
    call _ssh_write_string
    add r15d, eax

    ; Q_C (client's ECDH public key, as SSH string)
    lea rdi, [r14 + r15]
    lea rsi, [QC]
    mov edx, 32
    call _ssh_write_string
    add r15d, eax

    ; Q_S (server's ECDH public key, as SSH string)
    lea rdi, [r14 + r15]
    lea rsi, [QS_PUB]
    mov edx, 32
    call _ssh_write_string
    add r15d, eax

    ; K (shared secret as mpint)
    ; OpenSSH treats x25519 output as opaque 32-byte big-endian integer
    ; (no LE-to-BE reversal). We must match this behavior.
    ; mpint format: 4-byte len + value, with leading 0x00 if high bit set
    %define K_MPINT rbp - 248  ; 40 bytes max

    ; Save r15d before K mpint (to know offset of K in hash input)
    mov [rbp - 252], r15d

    ; Copy SHARED directly into K_MPINT+5 (leaving room for potential leading zero)
    lea rdi, [K_MPINT + 5]
    lea rsi, [SHARED]
    mov ecx, 32
    rep movsb

    ; Check if high bit of first byte is set (need leading zero for positive mpint)
    movzx eax, byte [K_MPINT + 5]
    test al, 0x80
    jz .no_leading_zero

    ; Insert leading zero
    mov byte [K_MPINT + 4], 0
    ; Length = 33
    mov eax, 33
    bswap eax
    mov [K_MPINT], eax

    ; Write mpint to hash input
    lea rdi, [r14 + r15]
    lea rsi, [K_MPINT]
    mov ecx, 37             ; 4 + 33
    rep movsb
    add r15d, 37
    jmp .hash_k_done

.no_leading_zero:
    ; Skip leading zero bytes
    lea rsi, [K_MPINT + 5]
    mov ecx, 32
    xor edx, edx            ; count of leading zeros
.skip_zeros:
    cmp ecx, 1
    jle .zeros_done
    cmp byte [rsi + rdx], 0
    jne .zeros_done
    inc edx
    dec ecx
    jmp .skip_zeros
.zeros_done:
    ; ecx = significant bytes, rdx = leading zeros to skip
    ; Check if top bit of first significant byte is set
    movzx eax, byte [rsi + rdx]
    test al, 0x80
    jz .mpint_no_pad

    ; Need padding byte
    dec rdx                  ; back up one byte
    mov byte [rsi + rdx], 0  ; insert zero
    inc ecx                  ; one more byte

.mpint_no_pad:
    ; Write length
    mov eax, ecx
    bswap eax
    lea rdi, [r14 + r15]
    mov [rdi], eax
    add rdi, 4
    ; Copy significant bytes
    lea rsi, [K_MPINT + 5]
    add rsi, rdx
    push rcx
    rep movsb
    pop rcx
    add ecx, 4
    add r15d, ecx

.hash_k_done:
    ; Debug: dump K mpint bytes from hash input
    mov eax, [rbp - 252]        ; offset where K starts
    lea rdi, [rel msg_dbg_mpint]
    lea rsi, [r14 + rax]
    mov edx, r15d
    sub edx, eax                ; K mpint length
    cmp edx, 40
    jbe .mpint_dump_ok
    mov edx, 40
.mpint_dump_ok:
    call _log_hex

    ; Compute H = SHA-256(hash_input)
    lea rdi, [r14]           ; hash input
    mov esi, r15d            ; hash input length
    lea rdx, [r12 + SESS_KEX_EXCHANGE_HASH]
    call _sha256_hash

    ; Debug: dump hash input length, first 64 bytes, H, and public key
    ; Hash input length as hex
    lea rdi, [rel msg_dbg_hashlen]
    lea rsi, [rbp - 256]
    mov eax, r15d
    bswap eax
    mov [rbp - 256], eax
    mov edx, 4
    call _log_hex

    ; First 64 bytes of hash input
    lea rdi, [rel msg_dbg_hash_in]
    lea rsi, [r14]
    mov edx, 64
    call _log_hex

    ; Exchange hash H
    lea rdi, [rel msg_dbg_hash]
    lea rsi, [r12 + SESS_KEX_EXCHANGE_HASH]
    mov edx, 32
    call _log_hex

    ; Host public key
    lea rdi, [rel msg_dbg_pubkey]
    lea rsi, [r12 + SESS_HOST_KEY_PUB]
    mov edx, 32
    call _log_hex

    ; K_S blob
    lea rdi, [rel msg_dbg_ks]
    lea rsi, [KS_BLOB]
    mov edx, 51
    call _log_hex

    ; If this is the first KEX, H becomes the session_id
    ; Check if session_id is zero
    mov rax, [r12 + SESS_SESSION_ID]
    or rax, [r12 + SESS_SESSION_ID + 8]
    or rax, [r12 + SESS_SESSION_ID + 16]
    or rax, [r12 + SESS_SESSION_ID + 24]
    test rax, rax
    jnz .session_id_set

    lea rdi, [r12 + SESS_SESSION_ID]
    lea rsi, [r12 + SESS_KEX_EXCHANGE_HASH]
    mov ecx, 32
    rep movsb

.session_id_set:
    ; --- Step 7: Sign H with Ed25519 ---
    %define SIGNATURE rbp - 312  ; 64 bytes

    lea rdi, [r12 + SESS_HOST_KEY_PRIV]   ; sk
    lea rsi, [r12 + SESS_HOST_KEY_PUB]    ; pk
    lea rdx, [r12 + SESS_KEX_EXCHANGE_HASH] ; message = H
    mov ecx, 32                             ; message length
    lea r8, [SIGNATURE]
    call _ed25519_sign

    ; Debug: dump signature
    lea rdi, [rel msg_dbg_sig]
    lea rsi, [SIGNATURE]
    mov edx, 64
    call _log_hex

    ; --- Step 8: Send KEX_ECDH_REPLY ---
    lea rdi, [rel msg_kex_reply]
    call _log_str

    ; Build KEX_ECDH_REPLY payload:
    ; SSH string K_S (host key blob)
    ; SSH string Q_S (server's ephemeral pubkey)
    ; SSH string signature blob

    lea r14, [kex_payload_buf]
    xor r15d, r15d

    ; K_S blob as SSH string
    lea rdi, [r14]
    lea rsi, [KS_BLOB]
    mov edx, ebx             ; ebx still has KS_BLOB_LEN from earlier
    call _ssh_write_string
    add r15d, eax

    ; Q_S as SSH string
    lea rdi, [r14 + r15]
    lea rsi, [QS_PUB]
    mov edx, 32
    call _ssh_write_string
    add r15d, eax

    ; Signature blob: SSH string "ssh-ed25519" + SSH string <64-byte sig>
    ; Total sig blob = 4 + 11 + 4 + 64 = 83 bytes
    ; Wrap it as SSH string: 4 + 83 = 87

    ; Build sig blob in kex_temp
    lea rdi, [kex_temp]
    lea rsi, [ssh_ed25519_str]
    mov edx, ssh_ed25519_len
    call _ssh_write_string
    mov r13d, eax

    lea rdi, [kex_temp]
    add rdi, r13
    lea rsi, [SIGNATURE]
    mov edx, 64
    call _ssh_write_string
    add r13d, eax            ; r13d = sig blob length

    ; Write sig blob as SSH string
    lea rdi, [r14 + r15]
    lea rsi, [kex_temp]
    mov edx, r13d
    call _ssh_write_string
    add r15d, eax

    ; Debug: dump the reply payload
    lea rdi, [rel msg_dbg_reply]
    lea rsi, [kex_payload_buf]
    mov edx, r15d
    cmp edx, 128
    jbe .reply_dump_ok
    mov edx, 128
.reply_dump_ok:
    call _log_hex

    ; Debug: dump reply payload length
    mov eax, r15d
    bswap eax
    mov [rbp - 280], eax
    lea rdi, [rel msg_dbg_reply_len]
    lea rsi, [rbp - 280]
    mov edx, 4
    call _log_hex

    ; Send KEX_ECDH_REPLY packet
    mov rdi, r12
    mov esi, SSH_MSG_KEX_ECDH_REPLY
    lea rdx, [kex_payload_buf]
    mov ecx, r15d
    call _ssh_packet_send
    test eax, eax
    jnz .kex_fail

    lea rdi, [rel msg_kex_done]
    call _log_str

    xor eax, eax
    jmp .kex_done

.kex_recv_fail:
    lea rdi, [rel msg_kex_recv_fail]
    call _log_str
    jmp .kex_fail

.kex_type_fail:
    lea rdi, [rel msg_kex_type_bad]
    call _log_str
    jmp .kex_fail

.kex_fail:
    lea rdi, [rel msg_kex_fail]
    call _log_str
    mov eax, -1

.kex_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 512
    pop rbp
    ret
