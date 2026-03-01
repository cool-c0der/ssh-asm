; =============================================================================
; test_chacha20poly1305.asm — OpenSSH ChaCha20-Poly1305 AEAD round-trip test
;
; Tests: encrypt then decrypt, verify plaintext matches
; Also tests: decrypt tampered ciphertext returns -1
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
; Test key: 64 bytes (K2[0..31] || K1[32..63])
test_keys:
    ; K2 (main key)
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ; K1 (header key)
    db 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    db 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    db 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
    db 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f

; Test plaintext: 4-byte length prefix + 20 bytes payload = 24 bytes total
test_plain:
    db 0x00, 0x00, 0x00, 0x14    ; packet length = 20
    db "Hello SSH World!!!!!"    ; 20 bytes payload
test_plain_len equ 24

msg_pass_rt: db "PASS: ChaCha20-Poly1305 round-trip", 10
msg_pass_rt_len equ $ - msg_pass_rt
msg_fail_rt: db "FAIL: ChaCha20-Poly1305 round-trip", 10
msg_fail_rt_len equ $ - msg_fail_rt
msg_pass_tamper: db "PASS: ChaCha20-Poly1305 tamper detect", 10
msg_pass_tamper_len equ $ - msg_pass_tamper
msg_fail_tamper: db "FAIL: ChaCha20-Poly1305 tamper detect", 10
msg_fail_tamper_len equ $ - msg_fail_tamper
msg_got: db "Got:    ", 0
msg_exp: db "Expect: ", 0

section .bss
    ciphertext: resb 64          ; 24 + 16 tag = 40, padded
    decrypted: resb 64
    hexbuf: resb 4

section .text

extern _chachapoly_encrypt
extern _chachapoly_open
extern _memcmp
extern _hex_byte
extern _sys_exit
extern _sys_write
extern _mem_init

_write_stderr:
    mov rdi, 2
    SYSCALL SYS_write
    ret

_dump_hex:
    ; rdi = data, esi = len
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    xor ebx, ebx
.loop:
    cmp ebx, r13d
    jge .done
    movzx esi, byte [r12 + rbx]
    lea rdi, [hexbuf]
    call _hex_byte
    lea rsi, [hexbuf]
    mov edx, 2
    call _write_stderr
    inc ebx
    jmp .loop
.done:
    pop r13
    pop r12
    pop rbx
    push 0x0a
    mov rsi, rsp
    mov edx, 1
    call _write_stderr
    add rsp, 8
    ret

global _main
_main:
    FUNC_ENTER
    SAVE_CALLEE
    call _mem_init

    ; --- Test 1: Encrypt ---
    ; chachapoly_encrypt(keys, seqno, plaintext, total_len, output)
    lea rdi, [test_keys]
    mov esi, 42                  ; seqno = 42
    lea rdx, [test_plain]
    mov ecx, test_plain_len      ; 24
    lea r8, [ciphertext]
    call _chachapoly_encrypt

    ; Print ciphertext + tag (24 + 16 = 40 bytes)
    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [ciphertext]
    mov esi, 40
    call _dump_hex

    ; --- Test 2: Decrypt ---
    ; chachapoly_open(keys, seqno, ciphertext, cipher_len_with_tag, output)
    lea rdi, [test_keys]
    mov esi, 42
    lea rdx, [ciphertext]
    mov ecx, 40                  ; 24 data + 16 tag
    lea r8, [decrypted]
    call _chachapoly_open
    test eax, eax
    jnz .fail_rt

    ; Compare decrypted with original plaintext
    lea rdi, [decrypted]
    lea rsi, [test_plain]
    mov edx, test_plain_len
    call _memcmp
    test eax, eax
    jnz .fail_rt

    lea rsi, [msg_pass_rt]
    mov edx, msg_pass_rt_len
    call _write_stderr
    jmp .test_tamper

.fail_rt:
    lea rsi, [msg_fail_rt]
    mov edx, msg_fail_rt_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test_tamper:
    ; --- Test 3: Tamper detection ---
    ; Flip a byte in ciphertext, verify open returns -1
    xor byte [ciphertext + 10], 0xFF

    lea rdi, [test_keys]
    mov esi, 42
    lea rdx, [ciphertext]
    mov ecx, 40
    lea r8, [decrypted]
    call _chachapoly_open
    cmp eax, -1
    jne .fail_tamper

    lea rsi, [msg_pass_tamper]
    mov edx, msg_pass_tamper_len
    call _write_stderr
    xor edi, edi
    call _sys_exit

.fail_tamper:
    lea rsi, [msg_fail_tamper]
    mov edx, msg_fail_tamper_len
    call _write_stderr
    mov edi, 1
    call _sys_exit
