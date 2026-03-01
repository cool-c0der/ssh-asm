; =============================================================================
; bignum.asm — 256-bit and 512-bit arithmetic
;
; Numbers are 4-limb little-endian uint64: n = limb[0] + limb[1]*2^64 + ...
; 512-bit results use 8 limbs.
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

; bn256_add(result, a, b) -> carry (0 or 1)
; result = a + b (mod 2^256), returns carry
; rdi=result, rsi=a, rdx=b
global _bn256_add
_bn256_add:
    mov rax, [rsi]
    add rax, [rdx]
    mov [rdi], rax

    mov rax, [rsi + 8]
    adc rax, [rdx + 8]
    mov [rdi + 8], rax

    mov rax, [rsi + 16]
    adc rax, [rdx + 16]
    mov [rdi + 16], rax

    mov rax, [rsi + 24]
    adc rax, [rdx + 24]
    mov [rdi + 24], rax

    sbb rax, rax            ; rax = -carry (0 or -1)
    neg rax                 ; rax = carry (0 or 1)
    ret

; bn256_sub(result, a, b) -> borrow (0 or 1)
; result = a - b (mod 2^256), returns borrow
; rdi=result, rsi=a, rdx=b
global _bn256_sub
_bn256_sub:
    mov rax, [rsi]
    sub rax, [rdx]
    mov [rdi], rax

    mov rax, [rsi + 8]
    sbb rax, [rdx + 8]
    mov [rdi + 8], rax

    mov rax, [rsi + 16]
    sbb rax, [rdx + 16]
    mov [rdi + 16], rax

    mov rax, [rsi + 24]
    sbb rax, [rdx + 24]
    mov [rdi + 24], rax

    sbb rax, rax
    neg rax                 ; borrow
    ret

; bn256_mul(result, a, b)
; result = a * b (512-bit result, 8 limbs)
; rdi=result (64 bytes), rsi=a (4 limbs), rdx=b (4 limbs)
global _bn256_mul
_bn256_mul:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; result
    mov r13, rsi            ; a
    mov r14, rdx            ; b

    ; Zero result (8 limbs = 64 bytes)
    xor eax, eax
    mov [r12], rax
    mov [r12 + 8], rax
    mov [r12 + 16], rax
    mov [r12 + 24], rax
    mov [r12 + 32], rax
    mov [r12 + 40], rax
    mov [r12 + 48], rax
    mov [r12 + 56], rax

    ; Schoolbook: result += a[i] * b[j] at position i+j
    ; Outer loop: i = 0..3
    xor r15d, r15d          ; i
.outer:
    mov rbx, [r13 + r15*8]  ; a[i]
    test rbx, rbx
    jz .skip_row

    xor ecx, ecx            ; j
    xor r8, r8              ; carry
.inner:
    ; result[i+j] += a[i] * b[j] + carry
    mov rax, rbx            ; a[i]
    mul qword [r14 + rcx*8] ; rdx:rax = a[i] * b[j]

    ; Add carry from previous column
    add rax, r8
    adc rdx, 0
    mov r8, rdx             ; new carry high

    ; Add to result[i+j]
    lea r9, [r15 + rcx]     ; position = i + j
    add [r12 + r9*8], rax
    adc r8, 0               ; propagate carry

    inc ecx
    cmp ecx, 4
    jl .inner

    ; Store final carry at result[i+4]
    lea r9, [r15 + 4]
    add [r12 + r9*8], r8

.skip_row:
    inc r15
    cmp r15, 4
    jl .outer

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; bn256_cmp(a, b) -> -1 if a<b, 0 if a==b, 1 if a>b
; rdi=a, rsi=b
global _bn256_cmp
_bn256_cmp:
    ; Compare from most significant limb
    mov rax, [rdi + 24]
    cmp rax, [rsi + 24]
    ja .gt
    jb .lt

    mov rax, [rdi + 16]
    cmp rax, [rsi + 16]
    ja .gt
    jb .lt

    mov rax, [rdi + 8]
    cmp rax, [rsi + 8]
    ja .gt
    jb .lt

    mov rax, [rdi]
    cmp rax, [rsi]
    ja .gt
    jb .lt

    xor eax, eax
    ret
.gt:
    mov eax, 1
    ret
.lt:
    mov eax, -1
    ret

; bn256_copy(dst, src)
; rdi=dst, rsi=src
global _bn256_copy
_bn256_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    ret

; bn256_zero(dst)
; rdi=dst
global _bn256_zero
_bn256_zero:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; bn256_is_zero(a) -> 1 if zero, 0 otherwise
; rdi=a
global _bn256_is_zero
_bn256_is_zero:
    mov rax, [rdi]
    or rax, [rdi + 8]
    or rax, [rdi + 16]
    or rax, [rdi + 24]
    test rax, rax
    setz al
    movzx eax, al
    ret

; bn256_set_word(dst, word)
; Set 256-bit number from a single 64-bit word
; rdi=dst, rsi=word
global _bn256_set_word
_bn256_set_word:
    mov [rdi], rsi
    xor eax, eax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    ret

; bn256_cswap(a, b, swap)
; Constant-time conditional swap: if swap != 0, swap a and b
; rdi=a, rsi=b, edx=swap
global _bn256_cswap
_bn256_cswap:
    test edx, edx
    jz .no_swap_ret
    ; Create mask: all 1s if swap, all 0s if not
    neg edx                 ; edx = 0 or 0xFFFFFFFF
    movsxd rdx, edx         ; sign-extend to 64 bits

    ; For each limb: diff = (a^b) & mask; a ^= diff; b ^= diff
    mov rax, [rdi]
    mov rcx, [rsi]
    mov r8, rax
    xor r8, rcx
    and r8, rdx
    xor rax, r8
    xor rcx, r8
    mov [rdi], rax
    mov [rsi], rcx

    mov rax, [rdi + 8]
    mov rcx, [rsi + 8]
    mov r8, rax
    xor r8, rcx
    and r8, rdx
    xor rax, r8
    xor rcx, r8
    mov [rdi + 8], rax
    mov [rsi + 8], rcx

    mov rax, [rdi + 16]
    mov rcx, [rsi + 16]
    mov r8, rax
    xor r8, rcx
    and r8, rdx
    xor rax, r8
    xor rcx, r8
    mov [rdi + 16], rax
    mov [rsi + 16], rcx

    mov rax, [rdi + 24]
    mov rcx, [rsi + 24]
    mov r8, rax
    xor r8, rcx
    and r8, rdx
    xor rax, r8
    xor rcx, r8
    mov [rdi + 24], rax
    mov [rsi + 24], rcx

.no_swap_ret:
    ret
