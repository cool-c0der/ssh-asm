; =============================================================================
; test_aes.asm — AES-128 test with NIST SP 800-38A vector (ECB)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
; NIST SP 800-38A, F.1.1 — AES-128 ECB Encrypt
; Key: 2b7e151628aed2a6abf7158809cf4f3c
aes128_key:
    db 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6
    db 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c

; Plaintext: 6bc1bee22e409f96e93d7e117393172a
aes128_plain:
    db 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96
    db 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a

; Expected ciphertext: 3ad77bb40d7a3660a89ecaf32466ef97
aes128_expected:
    db 0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60
    db 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97

; AES-256 key (NIST SP 800-38A F.5.1)
aes256_key:
    db 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe
    db 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81
    db 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7
    db 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4

aes256_plain:
    db 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96
    db 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a

aes256_expected:
    db 0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c
    db 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8

msg_pass128: db "PASS: AES-128-ECB", 10
msg_pass128_len equ $ - msg_pass128
msg_fail128: db "FAIL: AES-128-ECB", 10
msg_fail128_len equ $ - msg_fail128
msg_pass256: db "PASS: AES-256-ECB", 10
msg_pass256_len equ $ - msg_pass256
msg_fail256: db "FAIL: AES-256-ECB", 10
msg_fail256_len equ $ - msg_fail256
msg_got: db "Got:    ", 0
msg_exp: db "Expect: ", 0

section .bss
align 16
    schedule: resb 256      ; key schedule (up to 240 bytes, 16-aligned)
    cipher_out: resb 16
    hexbuf: resb 4

section .text

extern _aes128_expand_key
extern _aes256_expand_key
extern _aes_encrypt_block
extern _memcmp
extern _hex_byte
extern _sys_exit
extern _sys_write
extern _mem_init

_write_stderr:
    mov rdi, 2
    SYSCALL SYS_write
    ret

_dump_hex16:
    push rbx
    push r12
    mov r12, rdi
    xor ebx, ebx
.loop:
    cmp ebx, 16
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
    push 0x0a
    mov rsi, rsp
    mov edx, 1
    call _write_stderr
    add rsp, 8
    pop r12
    pop rbx
    ret

global _main
_main:
    FUNC_ENTER
    SAVE_CALLEE

    call _mem_init

    ; --- AES-128 Test ---
    lea rdi, [aes128_key]
    lea rsi, [schedule]
    call _aes128_expand_key

    lea rdi, [schedule]
    mov esi, 10              ; 10 rounds for AES-128
    lea rdx, [aes128_plain]
    lea rcx, [cipher_out]
    call _aes_encrypt_block

    ; Print
    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [aes128_expected]
    call _dump_hex16

    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [cipher_out]
    call _dump_hex16

    lea rdi, [cipher_out]
    lea rsi, [aes128_expected]
    mov edx, 16
    call _memcmp
    test eax, eax
    jnz .fail128

    lea rsi, [msg_pass128]
    mov edx, msg_pass128_len
    call _write_stderr
    jmp .test256

.fail128:
    lea rsi, [msg_fail128]
    mov edx, msg_fail128_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test256:
    ; --- AES-256 Test ---
    lea rdi, [aes256_key]
    lea rsi, [schedule]
    call _aes256_expand_key

    lea rdi, [schedule]
    mov esi, 14              ; 14 rounds for AES-256
    lea rdx, [aes256_plain]
    lea rcx, [cipher_out]
    call _aes_encrypt_block

    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [aes256_expected]
    call _dump_hex16

    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [cipher_out]
    call _dump_hex16

    lea rdi, [cipher_out]
    lea rsi, [aes256_expected]
    mov edx, 16
    call _memcmp
    test eax, eax
    jnz .fail256

    lea rsi, [msg_pass256]
    mov edx, msg_pass256_len
    call _write_stderr
    xor edi, edi
    call _sys_exit

.fail256:
    lea rsi, [msg_fail256]
    mov edx, msg_fail256_len
    call _write_stderr
    mov edi, 1
    call _sys_exit
