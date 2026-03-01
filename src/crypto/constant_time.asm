; =============================================================================
; constant_time.asm — Constant-time comparison and selection
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

; ct_memcmp(a, b, len) -> 0 if equal, nonzero if different
; Constant-time: always reads all bytes, OR-accumulates differences
; rdi=a, rsi=b, rdx=len
global _ct_memcmp
_ct_memcmp:
    xor eax, eax            ; accumulator
    test rdx, rdx
    jz .done
.loop:
    movzx ecx, byte [rdi]
    xor cl, [rsi]
    or al, cl
    inc rdi
    inc rsi
    dec rdx
    jnz .loop
.done:
    movzx eax, al           ; zero-extend result
    ret

; ct_select(a, b, flag) -> a if flag==0, b if flag!=0
; Branchless selection using cmov
; rdi=a, rsi=b, edx=flag
global _ct_select
_ct_select:
    mov rax, rdi             ; default = a
    test edx, edx
    cmovnz rax, rsi          ; if flag != 0, select b
    ret

; ct_select32(a, b, flag) -> uint32
; edi=a, esi=b, edx=flag
global _ct_select32
_ct_select32:
    mov eax, edi
    test edx, edx
    cmovnz eax, esi
    ret

; ct_zero_bytes(buf, len) — securely zero memory
; Uses volatile write (rep stosb) that won't be optimized out
; rdi=buf, rsi=len
global _ct_zero_bytes
_ct_zero_bytes:
    mov rcx, rsi
    xor al, al
    rep stosb
    ret
