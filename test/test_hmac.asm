; =============================================================================
; test_hmac.asm — HMAC-SHA-256 test with RFC 4231 test vectors
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .data
; RFC 4231 Test Case 2:
; Key = "Jefe" (4 bytes)
; Data = "what do ya want for nothing?" (28 bytes)
; HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c7
;                5a003f089d2739839dec58b964ec3843
hmac_key2: db "Jefe"
hmac_key2_len equ 4
hmac_msg2: db "what do ya want for nothing?"
hmac_msg2_len equ 28
hmac_expected2:
    db 0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e
    db 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7
    db 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83
    db 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43

; RFC 4231 Test Case 1:
; Key = 0x0b * 20
; Data = "Hi There" (8 bytes)
; HMAC-SHA-256 = b0344c61d8db38535ca8afceaf0bf12b
;                881dc200c9833da726e9376c2e32cff7
hmac_key1: times 20 db 0x0b
hmac_key1_len equ 20
hmac_msg1: db "Hi There"
hmac_msg1_len equ 8
hmac_expected1:
    db 0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53
    db 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b
    db 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7
    db 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7

msg_pass1: db "PASS: HMAC-SHA-256 (RFC 4231 TC1)", 10
msg_pass1_len equ $ - msg_pass1
msg_fail1: db "FAIL: HMAC-SHA-256 (RFC 4231 TC1)", 10
msg_fail1_len equ $ - msg_fail1
msg_pass2: db "PASS: HMAC-SHA-256 (RFC 4231 TC2)", 10
msg_pass2_len equ $ - msg_pass2
msg_fail2: db "FAIL: HMAC-SHA-256 (RFC 4231 TC2)", 10
msg_fail2_len equ $ - msg_fail2
msg_got: db "Got:    ", 0
msg_exp: db "Expect: ", 0

section .bss
    hmac_out: resb 32
    hexbuf: resb 4

section .text

extern _hmac_sha256
extern _memcmp
extern _hex_byte
extern _sys_exit
extern _sys_write
extern _mem_init

_write_stderr:
    mov rdi, 2
    SYSCALL SYS_write
    ret

_dump_hex32:
    push rbx
    push r12
    mov r12, rdi
    xor ebx, ebx
.loop:
    cmp ebx, 32
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

    ; --- Test Case 1 ---
    lea rdi, [hmac_key1]
    mov esi, hmac_key1_len
    lea rdx, [hmac_msg1]
    mov ecx, hmac_msg1_len
    lea r8, [hmac_out]
    call _hmac_sha256

    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [hmac_expected1]
    call _dump_hex32

    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [hmac_out]
    call _dump_hex32

    lea rdi, [hmac_out]
    lea rsi, [hmac_expected1]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail1

    lea rsi, [msg_pass1]
    mov edx, msg_pass1_len
    call _write_stderr
    jmp .test2

.fail1:
    lea rsi, [msg_fail1]
    mov edx, msg_fail1_len
    call _write_stderr
    mov edi, 1
    call _sys_exit

.test2:
    ; --- Test Case 2 ---
    lea rdi, [hmac_key2]
    mov esi, hmac_key2_len
    lea rdx, [hmac_msg2]
    mov ecx, hmac_msg2_len
    lea r8, [hmac_out]
    call _hmac_sha256

    lea rsi, [msg_exp]
    mov edx, 8
    call _write_stderr
    lea rdi, [hmac_expected2]
    call _dump_hex32

    lea rsi, [msg_got]
    mov edx, 8
    call _write_stderr
    lea rdi, [hmac_out]
    call _dump_hex32

    lea rdi, [hmac_out]
    lea rsi, [hmac_expected2]
    mov edx, 32
    call _memcmp
    test eax, eax
    jnz .fail2

    lea rsi, [msg_pass2]
    mov edx, msg_pass2_len
    call _write_stderr
    xor edi, edi
    call _sys_exit

.fail2:
    lea rsi, [msg_fail2]
    mov edx, msg_fail2_len
    call _write_stderr
    mov edi, 1
    call _sys_exit
