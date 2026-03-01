; =============================================================================
; test_sha256.asm — SHA-256 test with NIST vectors
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    test1_msg: db "abc"
    test1_len equ 3
    test1_expected:
        db 0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea
        db 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23
        db 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c
        db 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad

    test2_len equ 0
    test2_expected:
        db 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14
        db 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
        db 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c
        db 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55

    test3_msg: db "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    test3_len equ 56
    test3_expected:
        db 0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8
        db 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39
        db 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67
        db 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1

    msg_pass: db "PASS", 10
    msg_pass_len equ 5
    msg_fail: db "FAIL", 10
    msg_fail_len equ 5
    msg_test1: db "Test 1 - SHA-256(abc): ", 0
    msg_test2: db "Test 2 - SHA-256(): ", 0
    msg_test3: db "Test 3 - SHA-256(448bit): ", 0
    msg_got:   db "Got:    ", 0
    msg_expect: db "Expect: ", 0
    newline: db 10

section .bss
    digest: resb 32
    hexbuf: resb 128

section .text

extern _sha256_hash
extern _sha256_init
extern _sha256_update
extern _sha256_final
extern _memcmp
extern _sys_exit
extern _sys_write
extern _mem_init
extern _hex_byte

; write_stderr(buf, len)
_write_stderr:
    push rax
    push rcx
    push r11
    mov rdi, 2
    ; rsi=buf, rdx=len already set
    SYSCALL SYS_write
    pop r11
    pop rcx
    pop rax
    ret

; print null-terminated string to stderr
; rdi = string
_print_str:
    push rsi
    push rdx
    mov rsi, rdi
    ; find length
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

; dump 32 bytes as hex to stderr
; rdi = data pointer
_dump_hex32:
    push rbx
    push r12
    mov r12, rdi
    xor ebx, ebx
.loop:
    movzx esi, byte [r12 + rbx]
    lea rdi, [rel hexbuf]
    call _hex_byte
    ; write 2 hex chars
    lea rsi, [rel hexbuf]
    mov edx, 2
    call _write_stderr
    inc ebx
    cmp ebx, 32
    jl .loop
    ; newline
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

    ; --- Test 1: SHA-256("abc") ---
    lea rdi, [rel msg_test1]
    call _print_str

    lea rdi, [rel test1_msg]
    mov esi, test1_len
    lea rdx, [rel digest]
    call _sha256_hash

    ; Print expected
    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test1_expected]
    call _dump_hex32

    ; Print got
    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel digest]
    call _dump_hex32

    lea rdi, [rel digest]
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
    lea rdi, [rel msg_test2]
    call _print_str

    ; SHA-256("") - pass any valid ptr for data, len=0
    lea rdi, [rel digest]
    xor esi, esi
    lea rdx, [rel digest]
    call _sha256_hash

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel digest]
    call _dump_hex32

    lea rdi, [rel digest]
    lea rsi, [rel test2_expected]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail2
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .test3
.fail2:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test3:
    lea rdi, [rel msg_test3]
    call _print_str

    lea rdi, [rel test3_msg]
    mov esi, test3_len
    lea rdx, [rel digest]
    call _sha256_hash

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel digest]
    call _dump_hex32

    lea rdi, [rel digest]
    lea rsi, [rel test3_expected]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail3
    lea rsi, [rel msg_pass]
    mov edx, msg_pass_len
    call _write_stderr
    jmp .done
.fail3:
    lea rsi, [rel msg_fail]
    mov edx, msg_fail_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.done:
    xor edi, edi
    call _sys_exit
