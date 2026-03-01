; =============================================================================
; test_curve25519.asm — X25519 test with RFC 7748 vectors
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; RFC 7748 Section 6.1: Test Vector
    ; Alice's private key (scalar):
    test1_scalar:
        db 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d
        db 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45
        db 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a
        db 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a

    ; u-coordinate of base point (9):
    test1_u:
        db 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

    ; Expected output (Alice's public key):
    test1_expected:
        db 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54
        db 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a
        db 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4
        db 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a

    ; Second test vector (Bob):
    test2_scalar:
        db 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b
        db 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6
        db 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd
        db 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb

    test2_expected:
        db 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4
        db 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37
        db 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d
        db 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f

    msg_pass: db "PASS", 10
    msg_pass_len equ 5
    msg_fail: db "FAIL", 10
    msg_fail_len equ 5
    msg_test1: db "Test 1 - X25519(alice_sk, 9): ", 0
    msg_test2: db "Test 2 - X25519(bob_sk, 9): ", 0
    msg_got:   db "Got:    ", 0
    msg_expect: db "Expect: ", 0
    newline: db 10

section .bss
    result: resb 32
    hexbuf: resb 128

section .text

extern _x25519
extern _memcmp
extern _sys_exit
extern _mem_init
extern _hex_byte

_write_stderr:
    push rax
    push rcx
    push r11
    mov rdi, 2
    SYSCALL SYS_write
    pop r11
    pop rcx
    pop rax
    ret

_print_str:
    push rsi
    push rdx
    mov rsi, rdi
    xor edx, edx
.len:
    cmp byte [rsi + rdx], 0
    je .print
    inc edx
    jmp .len
.print:
    call _write_stderr
    pop rdx
    pop rsi
    ret

_dump_hex32:
    push rbx
    push r12
    mov r12, rdi
    xor ebx, ebx
.loop:
    movzx esi, byte [r12 + rbx]
    lea rdi, [rel hexbuf]
    call _hex_byte
    lea rsi, [rel hexbuf]
    mov edx, 2
    call _write_stderr
    inc ebx
    cmp ebx, 32
    jl .loop
    lea rsi, [rel newline]
    mov edx, 1
    call _write_stderr
    pop r12
    pop rbx
    ret

global _main
_main:
    FUNC_ENTER
    SAVE_CALLEE

    call _mem_init

    ; --- Test 1: X25519(alice_sk, basepoint) ---
    lea rdi, [rel msg_test1]
    call _print_str

    lea rdi, [rel result]
    lea rsi, [rel test1_scalar]
    lea rdx, [rel test1_u]
    call _x25519

    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test1_expected]
    call _dump_hex32

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel result]
    call _dump_hex32

    lea rdi, [rel result]
    lea rsi, [rel test1_expected]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail1
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .test2
.fail1:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test2:
    ; --- Test 2: X25519(bob_sk, basepoint) ---
    lea rdi, [rel msg_test2]
    call _print_str

    lea rdi, [rel result]
    lea rsi, [rel test2_scalar]
    lea rdx, [rel test1_u]           ; same basepoint
    call _x25519

    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test2_expected]
    call _dump_hex32

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel result]
    call _dump_hex32

    lea rdi, [rel result]
    lea rsi, [rel test2_expected]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail2
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .done
.fail2:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.done:
    xor edi, edi
    call _sys_exit
