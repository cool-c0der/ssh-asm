; =============================================================================
; test_chacha20.asm — ChaCha20 test with RFC 8439 Section 2.4.2 test vector
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
; RFC 8439 Section 2.3.2 — ChaCha20 block function test vector
; Key: 00:01:02:...1f
test_key:
    db 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
    db 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
    db 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f

; Nonce: 00:00:00:09:00:00:00:4a:00:00:00:00
test_nonce:
    db 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a
    db 0x00, 0x00, 0x00, 0x00

; Counter = 1
; Expected keystream block (first 64 bytes)
; From RFC 8439 Section 2.3.2
expected_block:
    db 0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15
    db 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4
    db 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03
    db 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e
    db 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09
    db 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2
    db 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9
    db 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e

msg_pass: db "PASS: ChaCha20 block (RFC 8439 2.3.2)", 10
msg_pass_len equ $ - msg_pass
msg_fail: db "FAIL: ChaCha20 block", 10
msg_fail_len equ $ - msg_fail
msg_got: db "Got:    ", 0
msg_exp: db "Expect: ", 0

section .bss
    output: resb 64
    hexbuf: resb 4

section .text

extern _chacha20_block
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
    ; newline
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

    ; chacha20_block(key, counter=1, nonce, output)
    lea rdi, [test_key]
    mov esi, 1               ; counter
    lea rdx, [test_nonce]
    lea rcx, [output]
    call _chacha20_block

    ; Print expected
    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [expected_block]
    mov esi, 64
    call _dump_hex

    ; Print got
    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [output]
    mov esi, 64
    call _dump_hex

    ; Compare
    lea rdi, [output]
    lea rsi, [expected_block]
    mov edx, 64
    call _memcmp
    test eax, eax
    jnz .fail

    lea rsi, [msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    xor edi, edi
    call _sys_exit

.fail:
    lea rsi, [msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit
