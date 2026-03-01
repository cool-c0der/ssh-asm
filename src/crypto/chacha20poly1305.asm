; =============================================================================
; chacha20poly1305.asm — OpenSSH ChaCha20-Poly1305 AEAD
;
; OpenSSH variant (NOT RFC 8439 AEAD):
; - Two separate ChaCha20 keys: K1 (header) and K2 (main)
; - K1 encrypts the 4-byte packet length (with nonce = seqno, counter = 0)
; - K2 encrypts the payload (counter = 0 for Poly1305 key, counter = 1+ for data)
; - Poly1305 MAC is computed over the encrypted packet length + encrypted payload
; - Nonce = 64-bit sequence number (big-endian, padded to 12 bytes with 4 zero bytes)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

extern _chacha20_block
extern _poly1305_mac

; chachapoly_seal(k1, k2, seqno, packet_len, payload, payload_len,
;                 out_enc_len, out_enc_payload, out_tag)
; Encrypt and authenticate:
; 1. Encrypt packet_len (4 bytes) with K1, counter=0, nonce=seqno
; 2. Generate Poly1305 key from K2 with counter=0
; 3. Encrypt payload with K2, counter=1
; 4. Poly1305 over (enc_len || enc_payload)
;
; rdi = K1 (32 bytes), rsi = K2 (32 bytes)
; edx = sequence number
; ecx = packet length (4 bytes, host byte order — will be big-endian in packet)
; r8  = payload data
; r9d = payload length
; Stack args: [rbp+16] = out_enc_len (4 bytes)
;             [rbp+24] = out_enc_payload (payload_len bytes)
;             [rbp+32] = out_tag (16 bytes)
;
; Simplified interface (for SSH transport layer):
; chachapoly_encrypt(keys, seqno, plaintext, plain_len, output)
; rdi = 64-byte key (K2 || K1, matching OpenSSH layout)
; esi = sequence number
; rdx = plaintext (4-byte length prefix + payload)
; ecx = total length (4 + payload_len)
; r8  = output buffer (4-byte enc_len + enc_payload + 16-byte tag)
global _chachapoly_encrypt
_chachapoly_encrypt:
    push rbp
    mov rbp, rsp
    sub rsp, 192             ; nonce(12) + keystream(64) + poly_key(32) + scratch(84)
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi             ; keys (K2 first 32, K1 next 32)
    mov r13d, esi            ; seqno
    mov r14, rdx             ; plaintext
    mov r15d, ecx            ; total_len
    mov rbx, r8              ; output

    ; Build nonce: 4 zero bytes + 8-byte big-endian seqno
    lea rax, [rbp - 12]
    mov dword [rax], 0       ; 4 zero bytes
    xor edx, edx
    mov eax, r13d
    bswap eax
    mov [rbp - 8], edx       ; high 4 bytes of seqno (0 for 32-bit seqno)
    mov [rbp - 4], eax       ; low 4 bytes (big-endian)

    ; --- Step 1: Encrypt 4-byte packet length with K1 ---
    ; K1 = keys + 32
    lea rdi, [r12 + 32]      ; K1
    xor esi, esi             ; counter = 0
    lea rdx, [rbp - 12]      ; nonce
    lea rcx, [rbp - 76]      ; keystream output (64 bytes)
    call _chacha20_block

    ; XOR first 4 bytes of keystream with plaintext length
    mov eax, [r14]           ; first 4 bytes of plaintext (packet length)
    xor eax, [rbp - 76]     ; XOR with keystream
    mov [rbx], eax           ; encrypted length

    ; --- Step 2: Generate Poly1305 key from K2, counter=0 ---
    mov rdi, r12             ; K2
    xor esi, esi             ; counter = 0
    lea rdx, [rbp - 12]      ; nonce
    lea rcx, [rbp - 76]      ; reuse keystream buffer
    call _chacha20_block
    ; Poly1305 key = first 32 bytes of keystream at [rbp-76]

    ; --- Step 3: Encrypt payload with K2, counter=1 ---
    mov eax, r15d
    sub eax, 4               ; payload_len
    jle .no_payload

    ; Copy payload to output (then encrypt in-place)
    lea rdi, [rbx + 4]       ; output + 4
    lea rsi, [r14 + 4]       ; plaintext + 4
    mov ecx, eax
    push rax
    rep movsb
    pop rax

    ; Encrypt with chacha20, counter starting at 1
    mov rdi, r12             ; K2
    mov esi, 1               ; counter = 1
    lea rdx, [rbp - 12]     ; nonce
    lea rcx, [rbx + 4]      ; data to encrypt (in-place)
    mov r8d, eax             ; payload length
    ; We need to call chacha20_crypt, but we have chacha20_block
    ; Let's do it block by block
    mov r13d, eax            ; remaining payload
    lea r14, [rbx + 4]       ; current output position
    mov r15d, 1              ; counter

.encrypt_loop:
    cmp r13d, 0
    jle .no_payload

    ; Generate keystream block
    mov rdi, r12
    mov esi, r15d
    lea rdx, [rbp - 12]
    lea rcx, [rbp - 140]    ; temp keystream at different offset
    call _chacha20_block

    ; XOR min(64, remaining) bytes
    mov ecx, 64
    cmp r13d, 64
    cmovl ecx, r13d
    xor eax, eax
.xor_payload:
    cmp eax, ecx
    jge .xor_payload_done
    movzx edx, byte [rbp - 140 + rax]
    xor [r14 + rax], dl
    inc eax
    jmp .xor_payload
.xor_payload_done:

    add r14, rcx
    sub r13d, ecx
    inc r15d
    jmp .encrypt_loop

.no_payload:
    ; --- Step 4: Poly1305 tag over (enc_len || enc_payload) ---
    ; Total authenticated data length = r15d (original total_len, but encrypted)
    ; We need original r15d which was clobbered... let me fix this
    ; Actually, output has: [0..3] = enc_len, [4..4+payload_len-1] = enc_payload
    ; We saved total_len at the start... but r15d was overwritten.
    ; Let's recalculate: total_len was 4 + payload_len
    ; We need the length of enc_len + enc_payload = total_len = 4 + payload_len

    ; Actually, the auth data length = 4 + payload_len = original total_len
    ; We need to recover it. Let's look at output buffer:
    ; Output: [enc_len(4)] [enc_payload(payload_len)] [tag(16)]
    ; The poly1305 input is the first (4 + payload_len) bytes = up to the tag

    ; Compute total_len: output - rbx gives current position
    ; Actually let's just save it better. The encrypt_loop end leaves r14 pointing past data.
    sub r14, rbx             ; r14 = bytes written so far = 4 + payload_len = total_len

    ; Poly1305(poly_key, authenticated_data, auth_len) -> tag
    lea rdi, [rbp - 76]     ; poly1305 key (32 bytes from step 2)
    mov rsi, rbx             ; authenticated data (enc_len + enc_payload)
    mov rdx, r14             ; auth data length
    lea rcx, [rbx + r14]    ; tag output (right after encrypted data)
    call _poly1305_mac

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

; chachapoly_open(keys, seqno, ciphertext, cipher_len, output) -> 0 ok, -1 bad MAC
; rdi = 64-byte key, esi = seqno
; rdx = ciphertext (4-byte enc_len + enc_payload + 16-byte tag)
; ecx = total length including tag
; r8 = output buffer (4-byte len + payload)
global _chachapoly_open
_chachapoly_open:
    push rbp
    mov rbp, rsp
    sub rsp, 192
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi             ; keys
    mov r13d, esi            ; seqno
    mov r14, rdx             ; ciphertext
    mov r15d, ecx            ; total len with tag
    mov rbx, r8              ; output

    ; Build nonce
    lea rax, [rbp - 12]
    mov dword [rax], 0
    xor edx, edx
    mov eax, r13d
    bswap eax
    mov [rbp - 8], edx
    mov [rbp - 4], eax

    ; Auth data length = total - 16 (tag)
    mov eax, r15d
    sub eax, 16
    mov r15d, eax            ; data_len (enc_len + enc_payload)

    ; Generate Poly1305 key from K2
    mov rdi, r12
    xor esi, esi
    lea rdx, [rbp - 12]
    lea rcx, [rbp - 76]
    call _chacha20_block

    ; Verify Poly1305 tag
    lea rdi, [rbp - 76]      ; poly key
    mov rsi, r14              ; ciphertext start
    movzx edx, r15w          ; auth data length
    lea rcx, [rbp - 176]     ; computed tag output
    call _poly1305_mac

    ; Compare computed tag with received tag
    lea rdi, [rbp - 176]
    lea rsi, [r14 + r15]     ; received tag is after data
    mov edx, 16
    extern _ct_memcmp
    call _ct_memcmp
    test eax, eax
    jnz .bad_mac

    ; Decrypt packet length with K1
    lea rdi, [r12 + 32]
    xor esi, esi
    lea rdx, [rbp - 12]
    lea rcx, [rbp - 76]
    call _chacha20_block

    mov eax, [r14]
    xor eax, [rbp - 76]
    mov [rbx], eax

    ; Decrypt payload with K2, counter=1
    mov eax, r15d
    sub eax, 4
    jle .open_done

    ; Copy encrypted payload to output
    lea rdi, [rbx + 4]
    lea rsi, [r14 + 4]
    mov ecx, eax
    push rax
    rep movsb
    pop rax

    ; Decrypt in place
    mov r13d, eax
    lea r14, [rbx + 4]
    mov r15d, 1

.decrypt_loop:
    cmp r13d, 0
    jle .open_done

    mov rdi, r12
    mov esi, r15d
    lea rdx, [rbp - 12]
    lea rcx, [rbp - 140]
    call _chacha20_block

    mov ecx, 64
    cmp r13d, 64
    cmovl ecx, r13d
    xor eax, eax
.xor_dec:
    cmp eax, ecx
    jge .xor_dec_done
    movzx edx, byte [rbp - 140 + rax]
    xor [r14 + rax], dl
    inc eax
    jmp .xor_dec
.xor_dec_done:
    add r14, rcx
    sub r13d, ecx
    inc r15d
    jmp .decrypt_loop

.open_done:
    xor eax, eax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

.bad_mac:
    mov eax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret
