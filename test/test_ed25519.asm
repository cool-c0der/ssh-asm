; =============================================================================
; test_ed25519.asm — Ed25519 test with RFC 8032 test vector 1
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; RFC 8032 Section 7.1, Test Vector 1
    ; Secret key (seed):
    test1_sk:
        db 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60
        db 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4
        db 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19
        db 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60

    ; Expected public key:
    test1_pk_expected:
        db 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7
        db 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a
        db 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25
        db 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a

    ; Message (empty for test vector 1):
    test1_msg_len equ 0

    ; Expected signature:
    test1_sig_expected:
        db 0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72
        db 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82, 0x8a
        db 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74
        db 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49, 0x01, 0x55
        db 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac
        db 0xc6, 0x1e, 0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b
        db 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24
        db 0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b

    msg_pass: db "PASS", 10
    msg_pass_len equ 5
    msg_fail: db "FAIL", 10
    msg_fail_len equ 5
    msg_test_pk: db "Test 1 - Ed25519 public key: ", 0
    msg_test_sig: db "Test 2 - Ed25519 sign(empty): ", 0
    msg_got:   db "Got:    ", 0
    msg_expect: db "Expect: ", 0
    newline: db 10

section .bss
    pk_out: resb 32
    sig_out: resb 64
    hexbuf: resb 256

section .text

extern _ed25519_publickey
extern _ed25519_sign
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

_dump_hex:
    ; rdi = data, esi = count
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
    lea rdi, [rel hexbuf]
    call _hex_byte
    lea rsi, [rel hexbuf]
    mov edx, 2
    call _write_stderr
    inc ebx
    jmp .loop
.done:
    lea rsi, [rel newline]
    mov edx, 1
    call _write_stderr
    pop r13
    pop r12
    pop rbx
    ret

global _main
_main:
    FUNC_ENTER
    SAVE_CALLEE

    call _mem_init

    ; --- Test 1: Public key derivation ---
    lea rdi, [rel msg_test_pk]
    call _print_str

    lea rdi, [rel test1_sk]
    lea rsi, [rel pk_out]
    call _ed25519_publickey

    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test1_pk_expected]
    mov esi, 32
    call _dump_hex

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel pk_out]
    mov esi, 32
    call _dump_hex

    lea rdi, [rel pk_out]
    lea rsi, [rel test1_pk_expected]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail_pk
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .test_sig

.fail_pk:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test_sig:
    ; --- Test 2: Sign empty message ---
    lea rdi, [rel msg_test_sig]
    call _print_str

    lea rdi, [rel test1_sk]
    lea rsi, [rel test1_pk_expected]  ; use expected pk
    lea rdx, [rel test1_sk]           ; msg ptr (unused, len=0)
    xor ecx, ecx                      ; msg_len = 0
    lea r8, [rel sig_out]
    call _ed25519_sign

    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test1_sig_expected]
    mov esi, 64
    call _dump_hex

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel sig_out]
    mov esi, 64
    call _dump_hex

    lea rdi, [rel sig_out]
    lea rsi, [rel test1_sig_expected]
    mov edx, 64
    call _memcmp
    test eax, eax
    jnz .fail_sig
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .done

.fail_sig:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.done:
    xor edi, edi
    call _sys_exit
