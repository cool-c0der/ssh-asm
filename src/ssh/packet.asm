; =============================================================================
; packet.asm — SSH Binary Packet Protocol (RFC 4253 Section 6)
;
; Packet format (unencrypted):
;   uint32    packet_length   (excluding self and MAC)
;   byte      padding_length
;   byte[n1]  payload
;   byte[n2]  padding (random, n2 >= 4)
;   byte[m]   MAC (if cipher active)
;
; With chacha20-poly1305@openssh.com:
;   4 bytes encrypted packet_length (using K1)
;   N bytes encrypted (padding_length + payload + padding) (using K2)
;   16 bytes Poly1305 tag
;
; Functions:
;   ssh_packet_send(session, type, payload, payload_len) -> 0 or -1
;   ssh_packet_recv(session, out_type, out_payload, out_len) -> 0 or -1
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
    msg_pkt_send: db "Sending packet type ", 0
    msg_pkt_recv: db "Received packet type ", 0
    msg_pkt_err:  db "Packet error", 0
    msg_pkt_read_hdr: db "pkt_recv: reading 4-byte header", 0
    msg_pkt_read_hdr_ok: db "pkt_recv: header read OK", 0
    msg_pkt_read_hdr_fail: db "pkt_recv: header read FAILED", 0
    msg_pkt_read_body_fail: db "pkt_recv: body read FAILED", 0
    msg_pkt_sanity_fail: db "pkt_recv: sanity check failed", 0
    msg_pkt_hdr_prefix: db "Header bytes: ", 0

section .bss
    ; Temporary packet assembly buffer (shared, not reentrant — fine for fork model)
    pkt_buf: resb 65536

section .text

extern _write_all
extern _read_exact
extern _write_be32
extern _read_be32
extern _random_bytes
extern _memcpy
extern _memset
extern _log_str
extern _log_msg
extern _log_hex
extern _chachapoly_encrypt
extern _chachapoly_open
extern _chacha20_block

; ssh_packet_send(session, type, payload, payload_len) -> 0 or -1
; rdi = session ptr, esi = msg type (byte)
; rdx = payload data (after type byte), ecx = payload data length
;
; The type byte is NOT included in the payload data.
; Total payload = 1 (type) + payload_data_len
global _ssh_packet_send
_ssh_packet_send:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session
    movzx r13d, sil         ; msg type
    mov r14, rdx            ; payload data
    mov r15d, ecx           ; payload data length

    ; Total payload = 1 (type byte) + payload_data_len
    lea eax, [r15d + 1]     ; total payload length
    mov [rbp - 4], eax      ; save total_payload_len

    ; Check cipher mode
    mov eax, [r12 + SESS_SEND_CIPHER]
    test eax, eax
    jnz .send_encrypted

    ; --- Unencrypted send ---
    ; Calculate padding: block_size = 8 for unencrypted
    ; packet_length = 1 (padding_length) + payload_len + padding
    ; Total (packet_length + 4) must be multiple of 8
    ; padding >= 4

    mov eax, [rbp - 4]      ; total_payload_len
    add eax, 5              ; 4 (pkt_len field) + 1 (padding_len field)
    mov ecx, eax
    add ecx, 7              ; round up
    and ecx, ~7             ; align to 8
    sub ecx, eax            ; padding needed
    add ecx, 8              ; ensure >= 4 (add one more block)
    cmp ecx, 4
    jge .pad_ok
    add ecx, 8
.pad_ok:
    mov [rbp - 8], ecx      ; padding_length

    ; packet_length = 1 + total_payload_len + padding
    mov eax, [rbp - 4]
    add eax, ecx
    inc eax                 ; +1 for padding_length byte
    mov [rbp - 12], eax     ; packet_length

    ; Build packet in pkt_buf
    lea rdi, [pkt_buf]

    ; Write packet_length (big-endian)
    mov eax, [rbp - 12]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; Write padding_length
    mov al, [rbp - 8]
    mov [rdi], al
    inc rdi

    ; Write message type
    mov [rdi], r13b
    inc rdi

    ; Write payload data
    test r15d, r15d
    jz .no_payload_data
    push rdi
    mov rsi, r14
    mov ecx, r15d
    rep movsb
    pop rdi
    add rdi, r15
.no_payload_data:

    ; Write random padding
    mov esi, [rbp - 8]      ; padding length (32-bit load, zero-extends to rsi)
    push rdi
    ; Generate random padding
    ; rdi = buffer position, rsi = padding length
    call _random_bytes
    pop rdi
    mov esi, [rbp - 8]      ; reload padding length
    add rdi, rsi

    ; Total bytes to send = 4 + packet_length
    mov eax, [rbp - 12]
    add eax, 4
    mov r15d, eax

    ; Send it
    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf]
    mov edx, r15d
    call _write_all
    test eax, eax
    jnz .send_error

    ; Increment send sequence number
    inc dword [r12 + SESS_SEQ_SEND]

    xor eax, eax
    jmp .send_done

.send_encrypted:
    ; --- Encrypted send (chacha20-poly1305@openssh.com) ---
    ; Build plaintext: [4-byte packet_length BE][padding_length][type][payload][padding]
    ; Then encrypt with chachapoly_encrypt

    ; Calculate padding: block_size = 8 for chacha20-poly1305
    ; OpenSSH requires packet_length % 8 == 0 for AEAD ciphers
    ; packet_length = 1 (padding_length byte) + total_payload_len + padding
    ; So base = 1 + total_payload_len, and we pad to align to 8
    mov eax, [rbp - 4]      ; total_payload_len (type + data)
    inc eax                  ; +1 for padding_length byte only (NOT +4 for pkt_len field)
    mov ecx, eax
    and ecx, 7              ; base % 8
    mov edx, 8
    sub edx, ecx            ; 8 - (base % 8); if base%8==0 → 8 (never 0)
    mov ecx, edx
    cmp ecx, 4
    jge .epad_ok
    add ecx, 8
.epad_ok:
    mov [rbp - 8], ecx      ; padding_length

    ; packet_length = 1 + total_payload + padding
    mov eax, [rbp - 4]
    add eax, ecx
    inc eax
    mov [rbp - 12], eax     ; packet_length

    ; Build plaintext in pkt_buf
    lea rdi, [pkt_buf]

    ; 4-byte packet_length (big-endian)
    mov eax, [rbp - 12]
    bswap eax
    mov [rdi], eax
    add rdi, 4

    ; padding_length byte
    mov al, [rbp - 8]
    mov [rdi], al
    inc rdi

    ; type byte
    mov [rdi], r13b
    inc rdi

    ; payload data
    test r15d, r15d
    jz .enc_no_payload
    mov rsi, r14
    mov ecx, r15d
    rep movsb
.enc_no_payload:

    ; random padding
    mov esi, [rbp - 8]
    push rdi
    call _random_bytes
    pop rdi

    ; Total plaintext = 4 + packet_length
    mov eax, [rbp - 12]
    add eax, 4
    mov r14d, eax            ; plaintext_len

    ; Encrypt: chachapoly_encrypt(keys, seqno, plaintext, len, output)
    ; Output goes to pkt_buf + 65536/2 to avoid overlap
    lea r8, [pkt_buf + 32768]
    lea rdi, [r12 + SESS_SEND_CHACHA_KEY]  ; 64-byte key (K2||K1)
    mov esi, [r12 + SESS_SEQ_SEND]
    lea rdx, [pkt_buf]      ; plaintext
    mov ecx, r14d            ; plaintext length
    call _chachapoly_encrypt

    ; Send: encrypted data (r14d bytes) + 16-byte tag
    mov eax, r14d
    add eax, 16             ; + poly1305 tag
    mov r15d, eax

    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf + 32768]
    mov edx, r15d
    call _write_all
    test eax, eax
    jnz .send_error

    inc dword [r12 + SESS_SEQ_SEND]

    xor eax, eax
    jmp .send_done

.send_error:
    mov eax, -1

.send_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret

; ssh_packet_recv(session, out_type, out_payload, out_len) -> 0 or -1
; rdi = session ptr
; rsi = pointer to byte (output: message type)
; rdx = pointer to buffer (output: payload after type, max SSH_MAX_PACKET_SIZE)
; rcx = pointer to uint32 (output: payload length after type)
;
; Returns 0 on success, -1 on error/EOF
global _ssh_packet_recv
_ssh_packet_recv:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; session
    mov r13, rsi            ; out_type ptr
    mov r14, rdx            ; out_payload ptr
    mov r15, rcx            ; out_len ptr

    ; Check cipher mode
    mov eax, [r12 + SESS_RECV_CIPHER]
    test eax, eax
    jnz .recv_encrypted

    ; --- Unencrypted receive ---
    ; Read 4-byte packet_length
    lea rdi, [rel msg_pkt_read_hdr]
    call _log_str

    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf]
    mov edx, 4
    call _read_exact
    test eax, eax
    jnz .recv_hdr_fail

    lea rdi, [rel msg_pkt_read_hdr_ok]
    call _log_str

    ; Debug: dump the 4 header bytes
    lea rdi, [rel msg_pkt_hdr_prefix]
    lea rsi, [pkt_buf]
    mov edx, 4
    call _log_hex

    ; Parse packet_length (big-endian)
    lea rdi, [pkt_buf]
    call _read_be32
    mov ebx, eax            ; packet_length

    ; Sanity check
    cmp ebx, SSH_MAX_PACKET_SIZE
    ja .recv_sanity_fail
    cmp ebx, 2              ; minimum: padding_length(1) + type(1)
    jb .recv_sanity_fail

    ; Read packet_length bytes
    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf + 4]
    mov edx, ebx
    call _read_exact
    test eax, eax
    jnz .recv_body_fail

    ; Parse padding_length
    movzx ecx, byte [pkt_buf + 4]

    ; Extract type byte
    movzx eax, byte [pkt_buf + 5]
    mov [r13], al

    ; Payload length = packet_length - padding_length - 1 (padding_len byte) - 1 (type byte included in payload calc)
    ; Actually: payload starts at offset 5 (after padding_length byte at offset 4)
    ; The "payload" in SSH includes the type byte
    ; Total payload = packet_length - 1 (padding_len) - padding
    ; Our out_payload excludes the type byte
    mov eax, ebx
    sub eax, 1              ; minus padding_length byte
    sub eax, ecx            ; minus padding
    ; eax = type_byte + payload_data_len
    dec eax                 ; subtract type byte
    jl .recv_error

    ; Store payload length (excluding type)
    mov [r15], eax

    ; Copy payload (after type byte)
    test eax, eax
    jz .recv_no_copy
    mov rdi, r14
    lea rsi, [pkt_buf + 6]  ; skip: 4(len) + 1(padlen) + 1(type)
    mov ecx, eax
    rep movsb
.recv_no_copy:

    ; Increment recv sequence number
    inc dword [r12 + SESS_SEQ_RECV]

    xor eax, eax
    jmp .recv_done

.recv_encrypted:
    ; --- Encrypted receive (chacha20-poly1305@openssh.com) ---
    ; First read 4 encrypted bytes (packet length)
    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf]
    mov edx, 4
    call _read_exact
    test eax, eax
    jnz .recv_error

    ; Decrypt packet length with K1, counter=0, nonce=seqno
    ; Build nonce: 4 zero bytes + 8-byte BE seqno
    sub rsp, 80             ; nonce(12) + keystream(64) + pad(4)
    mov dword [rsp], 0
    mov dword [rsp + 4], 0
    mov eax, [r12 + SESS_SEQ_RECV]
    bswap eax
    mov [rsp + 8], eax

    ; Generate keystream with K1 (at offset +32 in chacha key)
    lea rdi, [r12 + SESS_RECV_CHACHA_KEY + 32]  ; K1
    xor esi, esi                                  ; counter = 0
    lea rdx, [rsp]                                ; nonce
    lea rcx, [rsp + 12]                           ; keystream output
    call _chacha20_block

    ; Decrypt length: XOR first 4 bytes
    mov eax, [pkt_buf]
    xor eax, [rsp + 12]
    bswap eax
    mov ebx, eax            ; packet_length (host byte order)

    ; Sanity check
    cmp ebx, SSH_MAX_PACKET_SIZE
    ja .recv_enc_error
    cmp ebx, 2
    jb .recv_enc_error

    ; Read remaining bytes: packet_length + 16 (poly1305 tag)
    mov eax, ebx
    add eax, 16
    mov [rbp - 16], eax     ; save total remaining

    mov edi, [r12 + SESS_FD]
    lea rsi, [pkt_buf + 4]
    mov edx, eax
    call _read_exact
    test eax, eax
    jnz .recv_enc_error

    ; Now decrypt+verify with chachapoly_open
    ; Total ciphertext = 4 (enc_len) + packet_length + 16 (tag)
    mov eax, ebx
    add eax, 20             ; 4 + packet_length + 16
    mov ecx, eax

    lea rdi, [r12 + SESS_RECV_CHACHA_KEY]  ; 64-byte key
    mov esi, [r12 + SESS_SEQ_RECV]
    lea rdx, [pkt_buf]                      ; ciphertext
    ; ecx already set
    lea r8, [pkt_buf + 32768]               ; output buffer
    call _chachapoly_open
    test eax, eax
    jnz .recv_enc_error     ; MAC verification failed

    ; Parse decrypted packet (at pkt_buf + 32768)
    ; [0..3] = packet_length (already known)
    ; [4] = padding_length
    ; [5] = type byte
    ; [6..] = payload data
    movzx ecx, byte [pkt_buf + 32768 + 4]   ; padding_length
    movzx eax, byte [pkt_buf + 32768 + 5]   ; type
    mov [r13], al

    ; Payload length = packet_length - 1 (padlen byte) - padding - 1 (type)
    mov eax, ebx
    sub eax, 1
    sub eax, ecx
    dec eax
    jl .recv_enc_error

    mov [r15], eax

    ; Copy payload
    test eax, eax
    jz .recv_enc_no_copy
    mov rdi, r14
    lea rsi, [pkt_buf + 32768 + 6]
    mov ecx, eax
    rep movsb
.recv_enc_no_copy:

    add rsp, 80
    inc dword [r12 + SESS_SEQ_RECV]

    xor eax, eax
    jmp near .recv_done

.recv_enc_error:
    add rsp, 80
    jmp near .recv_error

.recv_hdr_fail:
    lea rdi, [rel msg_pkt_read_hdr_fail]
    call _log_str
    jmp near .recv_error

.recv_sanity_fail:
    lea rdi, [rel msg_pkt_sanity_fail]
    call _log_str
    jmp near .recv_error

.recv_body_fail:
    lea rdi, [rel msg_pkt_read_body_fail]
    call _log_str
    jmp near .recv_error

.recv_error:
    mov eax, -1

.recv_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret
