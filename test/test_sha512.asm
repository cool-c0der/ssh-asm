; =============================================================================
; test_sha512.asm — SHA-512 test with RFC 6234 vectors
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; Test 1: SHA-512("abc")
    test1_msg: db "abc"
    test1_len equ 3
    test1_expected:
        db 0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA
        db 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20, 0x41, 0x31
        db 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2
        db 0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A
        db 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8
        db 0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD
        db 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E
        db 0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F

    ; Test 2: SHA-512("")
    test2_len equ 0
    test2_expected:
        db 0xCF, 0x83, 0xE1, 0x35, 0x7E, 0xEF, 0xB8, 0xBD
        db 0xF1, 0x54, 0x28, 0x50, 0xD6, 0x6D, 0x80, 0x07
        db 0xD6, 0x20, 0xE4, 0x05, 0x0B, 0x57, 0x15, 0xDC
        db 0x83, 0xF4, 0xA9, 0x21, 0xD3, 0x6C, 0xE9, 0xCE
        db 0x47, 0xD0, 0xD1, 0x3C, 0x5D, 0x85, 0xF2, 0xB0
        db 0xFF, 0x83, 0x18, 0xD2, 0x87, 0x7E, 0xEC, 0x2F
        db 0x63, 0xB9, 0x31, 0xBD, 0x47, 0x41, 0x7A, 0x81
        db 0xA5, 0x38, 0x32, 0x7A, 0xF9, 0x27, 0xDA, 0x3E

    msg_pass: db "PASS", 10
    msg_pass_len equ 5
    msg_fail: db "FAIL", 10
    msg_fail_len equ 5
    msg_test1: db "Test 1 - SHA-512(abc): ", 0
    msg_test2: db "Test 2 - SHA-512(): ", 0
    msg_got:   db "Got:    ", 0
    msg_expect: db "Expect: ", 0
    newline: db 10

section .bss
    digest: resb 64
    hexbuf: resb 256

section .text

extern _sha512_hash
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

; Dump 64 bytes as hex
_dump_hex64:
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
    cmp ebx, 64
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

    ; --- Test 1: SHA-512("abc") ---
    lea rdi, [rel msg_test1]
    call _print_str

    lea rdi, [rel test1_msg]
    mov esi, test1_len
    lea rdx, [rel digest]
    call _sha512_hash

    lea rdi, [rel msg_expect]
    call _print_str
    lea rdi, [rel test1_expected]
    call _dump_hex64

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel digest]
    call _dump_hex64

    lea rdi, [rel digest]
    lea rsi, [rel test1_expected]
    mov edx, 64
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

    lea rdi, [rel digest]
    xor esi, esi
    lea rdx, [rel digest]
    call _sha512_hash

    lea rdi, [rel msg_got]
    call _print_str
    lea rdi, [rel digest]
    call _dump_hex64

    lea rdi, [rel digest]
    lea rsi, [rel test2_expected]
    mov edx, 64
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
