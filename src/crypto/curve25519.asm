; =============================================================================
; curve25519.asm — X25519 Diffie-Hellman (RFC 7748)
;
; Montgomery ladder on Curve25519: y^2 = x^3 + 486662*x^2 + x
; Uses only x-coordinates (Montgomery form).
; a24 = (486662 - 2) / 4 = 121665 (RFC 7748, used with AA in ladder)
;
; x25519(out, scalar, point) — compute shared secret
; x25519_basepoint(out, scalar) — compute public key (point = 9)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define FE_SIZE 40

section .text

extern _fe_zero
extern _fe_one
extern _fe_copy
extern _fe_add
extern _fe_sub
extern _fe_mul
extern _fe_inv
extern _fe_cswap
extern _fe_mul121666
extern _fe_tobytes
extern _fe_frombytes

; x25519(out, scalar, u_point)
; rdi = out (32 bytes), rsi = scalar (32 bytes), rdx = u_point (32 bytes)
global _x25519
_x25519:
    push rbp
    mov rbp, rsp
    ; Stack: x1, x2, z2, x3, z3 = 5 FE
    ;        a, b, c, d, e = 5 FE temps
    ;        scalar_copy = 32 bytes
    ; Total: 10 * 40 + 32 = 432, round to 448
    sub rsp, 448
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; out
    mov r13, rsi            ; scalar
    mov r14, rdx            ; u_point

    ; Stack offsets
    %define STK_X1      rbp - 40
    %define STK_X2      rbp - 80
    %define STK_Z2      rbp - 120
    %define STK_X3      rbp - 160
    %define STK_Z3      rbp - 200
    %define STK_A       rbp - 240
    %define STK_B       rbp - 280
    %define STK_C       rbp - 320
    %define STK_D       rbp - 360
    %define STK_E       rbp - 400
    %define STK_SCALAR  rbp - 432

    ; Copy and clamp scalar (RFC 7748 Section 5)
    lea rdi, [STK_SCALAR]
    mov rsi, r13
    mov ecx, 32
    rep movsb
    lea rax, [STK_SCALAR]
    and byte [rax], 0xF8
    and byte [rax + 31], 0x7F
    or  byte [rax + 31], 0x40

    ; Decode u-coordinate
    lea rdi, [STK_X1]
    mov rsi, r14
    call _fe_frombytes

    ; x2 = 1, z2 = 0
    lea rdi, [STK_X2]
    call _fe_one
    lea rdi, [STK_Z2]
    call _fe_zero

    ; x3 = u, z3 = 1
    lea rdi, [STK_X3]
    lea rsi, [STK_X1]
    call _fe_copy
    lea rdi, [STK_Z3]
    call _fe_one

    xor r15d, r15d          ; swap = 0
    mov ebx, 254            ; bit index

.ladder_loop:
    ; Get bit k_t from scalar
    mov ecx, ebx
    shr ecx, 3
    lea rax, [STK_SCALAR]
    movzx eax, byte [rax + rcx]
    mov ecx, ebx
    and ecx, 7
    shr eax, cl
    and eax, 1              ; k_t in eax

    ; swap ^= k_t
    xor r15d, eax
    mov r13d, eax           ; save k_t

    ; Conditional swap
    lea rdi, [STK_X2]
    lea rsi, [STK_X3]
    mov edx, r15d
    call _fe_cswap
    lea rdi, [STK_Z2]
    lea rsi, [STK_Z3]
    mov edx, r15d
    call _fe_cswap

    mov r15d, r13d          ; swap = k_t

    ; --- Montgomery ladder differential addition + doubling ---
    ; A = x2 + z2
    lea rdi, [STK_A]
    lea rsi, [STK_X2]
    lea rdx, [STK_Z2]
    call _fe_add

    ; B = x2 - z2
    lea rdi, [STK_B]
    lea rsi, [STK_X2]
    lea rdx, [STK_Z2]
    call _fe_sub

    ; C = x3 + z3
    lea rdi, [STK_C]
    lea rsi, [STK_X3]
    lea rdx, [STK_Z3]
    call _fe_add

    ; D = x3 - z3
    lea rdi, [STK_D]
    lea rsi, [STK_X3]
    lea rdx, [STK_Z3]
    call _fe_sub

    ; DA = D * A
    lea rdi, [STK_D]
    lea rsi, [STK_D]
    lea rdx, [STK_A]
    call _fe_mul

    ; CB = C * B
    lea rdi, [STK_C]
    lea rsi, [STK_C]
    lea rdx, [STK_B]
    call _fe_mul

    ; AA = A * A
    lea rdi, [STK_A]
    lea rsi, [STK_A]
    lea rdx, [STK_A]
    call _fe_mul

    ; BB = B * B
    lea rdi, [STK_B]
    lea rsi, [STK_B]
    lea rdx, [STK_B]
    call _fe_mul

    ; x3 = (DA + CB)^2
    lea rdi, [STK_X3]
    lea rsi, [STK_D]        ; DA
    lea rdx, [STK_C]        ; CB
    call _fe_add
    lea rdi, [STK_X3]
    lea rsi, [STK_X3]
    lea rdx, [STK_X3]
    call _fe_mul

    ; z3 = x1 * (DA - CB)^2
    lea rdi, [STK_Z3]
    lea rsi, [STK_D]        ; DA
    lea rdx, [STK_C]        ; CB
    call _fe_sub
    lea rdi, [STK_Z3]
    lea rsi, [STK_Z3]
    lea rdx, [STK_Z3]
    call _fe_mul
    lea rdi, [STK_Z3]
    lea rsi, [STK_Z3]
    lea rdx, [STK_X1]
    call _fe_mul

    ; E = AA - BB
    lea rdi, [STK_E]
    lea rsi, [STK_A]        ; AA
    lea rdx, [STK_B]        ; BB
    call _fe_sub

    ; x2 = AA * BB
    lea rdi, [STK_X2]
    lea rsi, [STK_A]        ; AA
    lea rdx, [STK_B]        ; BB
    call _fe_mul

    ; z2 = E * (AA + a24 * E)
    ; a24 * E
    lea rdi, [STK_D]        ; reuse D as temp
    lea rsi, [STK_E]
    call _fe_mul121666
    ; AA + a24*E
    lea rdi, [STK_D]
    lea rsi, [STK_D]
    lea rdx, [STK_A]        ; AA
    call _fe_add
    ; z2 = E * (AA + a24*E)
    lea rdi, [STK_Z2]
    lea rsi, [STK_E]
    lea rdx, [STK_D]
    call _fe_mul

    dec ebx
    jns .ladder_loop

    ; Final conditional swap
    lea rdi, [STK_X2]
    lea rsi, [STK_X3]
    mov edx, r15d
    call _fe_cswap
    lea rdi, [STK_Z2]
    lea rsi, [STK_Z3]
    mov edx, r15d
    call _fe_cswap

    ; Result = x2 * z2^(-1)
    lea rdi, [STK_A]
    lea rsi, [STK_Z2]
    call _fe_inv

    lea rdi, [STK_B]
    lea rsi, [STK_X2]
    lea rdx, [STK_A]
    call _fe_mul

    ; Serialize to output
    mov rdi, r12
    lea rsi, [STK_B]
    call _fe_tobytes

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 448
    pop rbp
    ret

; x25519_basepoint(out, scalar)
; rdi = out (32 bytes), rsi = scalar (32 bytes)
global _x25519_basepoint
_x25519_basepoint:
    push rbx
    sub rsp, 32
    mov rbx, rdi

    ; Write basepoint = 9 as 32-byte LE
    mov qword [rsp], 9
    mov qword [rsp + 8], 0
    mov qword [rsp + 16], 0
    mov qword [rsp + 24], 0

    mov rdi, rbx
    ; rsi already = scalar
    mov rdx, rsp
    call _x25519

    add rsp, 32
    pop rbx
    ret
