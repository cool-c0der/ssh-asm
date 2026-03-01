; =============================================================================
; test_poly1305.asm — Poly1305 test with RFC 8439 Section 2.5.2 vector
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
; RFC 8439 Section 2.5.2
; Key (32 bytes): r=85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
;                 s=01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
poly_key:
    db 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33
    db 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8
    db 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd
    db 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b

; Message: "Cryptographic Forum Research Group"
poly_msg: db "Cryptographic Forum Research Group"
poly_msg_len equ $ - poly_msg

; Expected tag: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
poly_expected:
    db 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6
    db 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9

msg_pass: db "PASS: Poly1305 (RFC 8439 2.5.2)", 10
msg_pass_len equ $ - msg_pass
msg_fail: db "FAIL: Poly1305", 10
msg_fail_len equ $ - msg_fail
msg_got: db "Got:    ", 0
msg_exp: db "Expect: ", 0

section .bss
    tag_out: resb 16
    hexbuf: resb 4

section .text

extern _poly1305_mac
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

    ; poly1305_mac(key, msg, msg_len, tag)
    lea rdi, [poly_key]
    lea rsi, [poly_msg]
    mov edx, poly_msg_len
    lea rcx, [tag_out]
    call _poly1305_mac

    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [poly_expected]
    call _dump_hex16

    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [tag_out]
    call _dump_hex16

    lea rdi, [tag_out]
    lea rsi, [poly_expected]
    mov edx, 16
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
