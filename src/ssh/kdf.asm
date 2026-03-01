; =============================================================================
; kdf.asm — SSH Key Derivation (RFC 4253 Section 7.2) + NEWKEYS
;
; Derives encryption keys after key exchange:
;   K1 || K2 = HASH(K || H || "X" || session_id)
;
; For chacha20-poly1305@openssh.com, each direction needs 64 bytes of key
; (K2=32 bytes main + K1=32 bytes header).
;
; Key derivation:
;   Initial: HASH(K || H || letter || session_id) = 32 bytes
;   Extension: HASH(K || H || K1) = next 32 bytes
;   Concatenate for 64 bytes total per direction
;
; Letters:
;   'A' = IV client->server (not used for chacha20-poly1305)
;   'B' = IV server->client (not used)
;   'C' = encryption key client->server
;   'D' = encryption key server->client
;   'E' = integrity key client->server (not used, AEAD)
;   'F' = integrity key server->client (not used, AEAD)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
    msg_newkeys_send: db "Sending NEWKEYS", 0
    msg_newkeys_recv: db "Received NEWKEYS", 0
    msg_newkeys_fail: db "NEWKEYS exchange failed", 0
    msg_keys_derived: db "Session keys derived", 0

section .bss
    kdf_hash_input: resb 256    ; buffer for hash input construction
    kdf_temp_key:   resb 64     ; temp key storage

section .text

extern _sha256_init
extern _sha256_update
extern _sha256_final
extern _sha256_hash
extern _ssh_packet_send
extern _ssh_packet_recv
extern _write_be32
extern _memcpy
extern _memset
extern _log_str

; _kdf_derive_key(K, K_len, H, session_id, letter, out, out_len)
; Derive a key using SSH KDF
; rdi = K (shared secret as mpint, including 4-byte length prefix)
; rsi = K_len (total mpint length including prefix)
; rdx = H (exchange hash, 32 bytes)
; rcx = session_id (32 bytes)
; r8b = letter ('A'-'F')
; r9  = output buffer
; [rbp+16] = output length (32 or 64)
;
; HASH(K || H || letter || session_id) = first 32 bytes
; HASH(K || H || first_32_bytes) = next 32 bytes (if needed)
_kdf_derive_key:
    push rbp
    mov rbp, rsp
    sub rsp, 256            ; SHA-256 context + temp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; K mpint
    mov r13, rsi            ; K_len
    mov r14, rdx            ; H
    mov r15, rcx            ; session_id
    mov [rbp - 1], r8b      ; letter
    mov rbx, r9             ; output

    %define KDF_CTX rbp - 128  ; SHA-256 context (112 bytes)

    ; First hash: HASH(K || H || letter || session_id)
    lea rdi, [KDF_CTX]
    call _sha256_init

    ; Feed K (mpint with length prefix)
    lea rdi, [KDF_CTX]
    mov rsi, r12
    mov rdx, r13
    call _sha256_update

    ; Feed H (32 bytes)
    lea rdi, [KDF_CTX]
    mov rsi, r14
    mov rdx, 32
    call _sha256_update

    ; Feed letter (1 byte)
    lea rdi, [KDF_CTX]
    lea rsi, [rbp - 1]
    mov rdx, 1
    call _sha256_update

    ; Feed session_id (32 bytes)
    lea rdi, [KDF_CTX]
    mov rsi, r15
    mov rdx, 32
    call _sha256_update

    ; Finalize -> first 32 bytes
    lea rdi, [KDF_CTX]
    mov rsi, rbx
    call _sha256_final

    ; Check if we need more than 32 bytes
    mov rax, [rbp + 16]     ; out_len
    cmp rax, 32
    jle .kdf_done

    ; Extension: HASH(K || H || first_32_bytes) -> next 32 bytes
    lea rdi, [KDF_CTX]
    call _sha256_init

    lea rdi, [KDF_CTX]
    mov rsi, r12
    mov rdx, r13
    call _sha256_update

    lea rdi, [KDF_CTX]
    mov rsi, r14
    mov rdx, 32
    call _sha256_update

    ; Feed the first 32 bytes we already derived
    lea rdi, [KDF_CTX]
    mov rsi, rbx
    mov rdx, 32
    call _sha256_update

    lea rdi, [KDF_CTX]
    lea rsi, [rbx + 32]
    call _sha256_final

.kdf_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 256
    pop rbp
    ret

; ssh_newkeys(session) -> 0 or -1
; Send/receive NEWKEYS and derive session keys
; rdi = session pointer
global _ssh_newkeys
_ssh_newkeys:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13

    mov r12, rdi            ; session

    ; --- Send NEWKEYS ---
    lea rdi, [rel msg_newkeys_send]
    call _log_str

    mov rdi, r12
    mov esi, SSH_MSG_NEWKEYS
    xor edx, edx            ; no payload
    xor ecx, ecx
    call _ssh_packet_send
    test eax, eax
    jnz .newkeys_fail

    ; --- Receive NEWKEYS ---
    mov rdi, r12
    lea rsi, [rbp - 1]      ; out_type
    lea rdx, [rbp - 64]     ; out_payload (unused)
    lea rcx, [rbp - 8]      ; out_len
    call _ssh_packet_recv
    test eax, eax
    jnz .newkeys_fail

    cmp byte [rbp - 1], SSH_MSG_NEWKEYS
    jne .newkeys_fail

    lea rdi, [rel msg_newkeys_recv]
    call _log_str

    ; --- Derive session keys ---
    ; Build K as mpint for the KDF
    ; K is the shared secret at SESS_KEX_SHARED_SECRET (32 bytes)
    ; OpenSSH treats x25519 output as opaque big-endian (no byte reversal)
    ; Need to encode as mpint (length prefix, leading 0x00 if high bit set)

    ; Copy shared secret directly (no reversal, matching exchange hash encoding)
    lea rsi, [r12 + SESS_KEX_SHARED_SECRET]
    lea rdi, [kdf_temp_key + 5]  ; leave room for length + potential padding
    mov ecx, 32
    rep movsb

    ; Skip leading zeros and handle mpint padding
    lea rsi, [kdf_temp_key + 5]
    mov ecx, 32
    xor edx, edx
.skip_lz:
    cmp ecx, 1
    jle .lz_done
    cmp byte [rsi + rdx], 0
    jne .lz_done
    inc edx
    dec ecx
    jmp .skip_lz
.lz_done:
    ; ecx = significant bytes, edx = zeros to skip
    ; Check high bit
    movzx eax, byte [rsi + rdx]
    test al, 0x80
    jz .mpint_ready

    ; Need leading zero byte
    dec rdx
    mov byte [rsi + rdx], 0
    inc ecx

.mpint_ready:
    ; Move data to start of kdf_temp_key + 4
    ; Calculate start pointer
    lea r13, [kdf_temp_key + 5]
    add r13, rdx             ; pointer to first significant byte
    mov ebx, ecx             ; significant length

    ; Write length prefix
    lea rdi, [kdf_temp_key]
    mov eax, ebx
    bswap eax
    mov [rdi], eax

    ; Move data right after length
    lea rdi, [kdf_temp_key + 4]
    mov rsi, r13
    cmp rdi, rsi
    je .no_move
    mov ecx, ebx
    rep movsb
.no_move:
    ; K mpint is at kdf_temp_key, total length = 4 + ebx
    lea eax, [ebx + 4]
    mov r13d, eax            ; K total length

    ; Derive keys for chacha20-poly1305@openssh.com
    ; Each direction needs 64 bytes (K2=32 main + K1=32 header)

    ; Key C: encryption client->server (recv key for us)
    push qword 64            ; out_len = 64
    lea rdi, [kdf_temp_key]
    mov rsi, r13             ; K_len
    lea rdx, [r12 + SESS_KEX_EXCHANGE_HASH]
    lea rcx, [r12 + SESS_SESSION_ID]
    mov r8b, 'C'
    lea r9, [r12 + SESS_RECV_CHACHA_KEY]
    call _kdf_derive_key
    add rsp, 8

    ; Key D: encryption server->client (send key for us)
    push qword 64
    lea rdi, [kdf_temp_key]
    mov rsi, r13
    lea rdx, [r12 + SESS_KEX_EXCHANGE_HASH]
    lea rcx, [r12 + SESS_SESSION_ID]
    mov r8b, 'D'
    lea r9, [r12 + SESS_SEND_CHACHA_KEY]
    call _kdf_derive_key
    add rsp, 8

    ; Set cipher mode to chacha20-poly1305 (3)
    mov dword [r12 + SESS_SEND_CIPHER], 3
    mov dword [r12 + SESS_RECV_CIPHER], 3

    ; Reset sequence numbers after NEWKEYS
    ; Actually, RFC says sequence numbers are NOT reset. They continue.
    ; (Sequence numbers increment across the entire connection.)

    lea rdi, [rel msg_keys_derived]
    call _log_str

    xor eax, eax
    jmp .newkeys_done

.newkeys_fail:
    lea rdi, [rel msg_newkeys_fail]
    call _log_str
    mov eax, -1

.newkeys_done:
    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret
