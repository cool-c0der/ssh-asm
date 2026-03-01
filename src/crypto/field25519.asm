; =============================================================================
; field25519.asm — GF(2^255 - 19) field arithmetic
;
; Elements are 5 limbs of 51 bits each (radix 2^51):
;   x = x[0] + x[1]*2^51 + x[2]*2^102 + x[3]*2^153 + x[4]*2^204
;
; Each limb stored as uint64 in a 40-byte array (5 * 8 bytes).
; Limbs may be slightly larger than 51 bits during computation;
; fe_reduce() brings them back to canonical form.
;
; p = 2^255 - 19
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define FE_LIMBS    5
%define FE_SIZE     40      ; 5 * 8 bytes
%define MASK51      0x7FFFFFFFFFFFF  ; (1 << 51) - 1

section .data
align 16
; p = 2^255 - 19 in 5-limb radix-2^51 representation
; limb[0] = 2^51 - 19, limb[1..4] = 2^51 - 1
fe_p:
    dq 0x7FFFFFFFFFFED     ; 2^51 - 19
    dq 0x7FFFFFFFFFFFF     ; 2^51 - 1
    dq 0x7FFFFFFFFFFFF
    dq 0x7FFFFFFFFFFFF
    dq 0x7FFFFFFFFFFFF

; 64-bit constants that cannot be used as immediates in AND/ADD/SUB/CMP
; (x86-64 only supports 32-bit sign-extended immediates for these ops)
mask51_val: dq 0x7FFFFFFFFFFFF     ; MASK51 = (1 << 51) - 1
two_p0_val: dq 0xFFFFFFFFFFFDA     ; 2*(2^51 - 19) = 2^52 - 38
two_p1_val: dq 0xFFFFFFFFFFFFE     ; 2*(2^51 - 1)  = 2^52 - 2
p0_val:     dq 0x7FFFFFFFFFFED     ; 2^51 - 19

section .text

; fe_zero(r)
; Set r = 0
global _fe_zero
_fe_zero:
    xor eax, eax
    mov [rdi], rax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    ret

; fe_one(r)
; Set r = 1
global _fe_one
_fe_one:
    mov qword [rdi], 1
    xor eax, eax
    mov [rdi + 8], rax
    mov [rdi + 16], rax
    mov [rdi + 24], rax
    mov [rdi + 32], rax
    ret

; fe_copy(dst, src)
global _fe_copy
_fe_copy:
    mov rax, [rsi]
    mov [rdi], rax
    mov rax, [rsi + 8]
    mov [rdi + 8], rax
    mov rax, [rsi + 16]
    mov [rdi + 16], rax
    mov rax, [rsi + 24]
    mov [rdi + 24], rax
    mov rax, [rsi + 32]
    mov [rdi + 32], rax
    ret

; fe_add(r, a, b)
; r = a + b (no reduction — caller must reduce or limbs stay < 2^52)
; rdi=r, rsi=a, rdx=b
global _fe_add
_fe_add:
    mov rax, [rsi]
    add rax, [rdx]
    mov [rdi], rax

    mov rax, [rsi + 8]
    add rax, [rdx + 8]
    mov [rdi + 8], rax

    mov rax, [rsi + 16]
    add rax, [rdx + 16]
    mov [rdi + 16], rax

    mov rax, [rsi + 24]
    add rax, [rdx + 24]
    mov [rdi + 24], rax

    mov rax, [rsi + 32]
    add rax, [rdx + 32]
    mov [rdi + 32], rax
    ret

; fe_sub(r, a, b)
; r = a - b (add 2p to avoid underflow, then carry)
; rdi=r, rsi=a, rdx=b
global _fe_sub
_fe_sub:
    push rbx

    ; Add 2p to a before subtracting b to ensure no underflow
    ; 2p limbs: 2*(2^51-19) = 2^52-38, 2*(2^51-1) = 2^52-2
    mov rax, [rsi]
    add rax, [two_p0_val]          ; 2*(2^51-19)
    sub rax, [rdx]
    mov [rdi], rax

    mov rax, [rsi + 8]
    add rax, [two_p1_val]      ; 2*(2^51-1)
    sub rax, [rdx + 8]
    mov [rdi + 8], rax

    mov rax, [rsi + 16]
    add rax, [two_p1_val]
    sub rax, [rdx + 16]
    mov [rdi + 16], rax

    mov rax, [rsi + 24]
    add rax, [two_p1_val]
    sub rax, [rdx + 24]
    mov [rdi + 24], rax

    mov rax, [rsi + 32]
    add rax, [two_p1_val]
    sub rax, [rdx + 32]
    mov [rdi + 32], rax

    ; Carry propagation to normalize
    mov rax, [rdi]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi], rax
    add [rdi + 8], rbx

    mov rax, [rdi + 8]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 8], rax
    add [rdi + 16], rbx

    mov rax, [rdi + 16]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 16], rax
    add [rdi + 24], rbx

    mov rax, [rdi + 24]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 24], rax
    add [rdi + 32], rbx

    mov rax, [rdi + 32]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 32], rax
    ; Carry from top wraps: multiply by 19 and add to limb[0]
    imul rbx, 19
    add [rdi], rbx

    pop rbx
    ret

; fe_mul(r, a, b)
; r = a * b mod p
; Uses schoolbook multiplication with intermediate 128-bit products
; rdi=r, rsi=a, rdx=b
global _fe_mul
_fe_mul:
    push rbp
    mov rbp, rsp
    sub rsp, 88              ; temp space FIRST (before pushes)
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; result
    mov r13, rsi            ; a
    mov r14, rdx            ; b

    ; Load a limbs
    mov r8, [r13]           ; a0
    mov r9, [r13 + 8]       ; a1
    mov r10, [r13 + 16]     ; a2
    mov r11, [r13 + 24]     ; a3
    mov r15, [r13 + 32]     ; a4

    ; Save raw b limbs to stack (handles aliasing: output may == b)
    ; [rbp-88]: b0, [rbp-80]: b1, [rbp-72]: b2, [rbp-64]: b3, [rbp-56]: b4
    mov rax, [r14]
    mov [rbp - 88], rax      ; b0
    mov rax, [r14 + 8]
    mov [rbp - 80], rax      ; b1
    mov rax, [r14 + 16]
    mov [rbp - 72], rax      ; b2
    mov rax, [r14 + 24]
    mov [rbp - 64], rax      ; b3
    mov rax, [r14 + 32]
    mov [rbp - 56], rax      ; b4

    ; Precompute b[i]*19 for reduction (since 2^255 ≡ 19 mod p)
    ; b1_19 = b[1]*19, b2_19 = b[2]*19, b3_19 = b[3]*19, b4_19 = b[4]*19
    mov rax, [rbp - 80]
    imul rax, 19
    mov [rbp - 48], rax      ; b1_19
    mov rax, [rbp - 72]
    imul rax, 19
    mov [rbp - 40], rax      ; b2_19
    mov rax, [rbp - 64]
    imul rax, 19
    mov [rbp - 32], rax      ; b3_19
    mov rax, [rbp - 56]
    imul rax, 19
    mov [rbp - 24], rax      ; b4_19

    ; t0 = a0*b0 + a1*b4_19 + a2*b3_19 + a3*b2_19 + a4*b1_19
    mov rax, r8
    mul qword [rbp - 88]    ; a0*b0
    mov rbx, rax
    mov rcx, rdx

    mov rax, r9
    mul qword [rbp - 24]    ; a1*b4_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r10
    mul qword [rbp - 32]    ; a2*b3_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r11
    mul qword [rbp - 40]    ; a3*b2_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r15
    mul qword [rbp - 48]    ; a4*b1_19
    add rbx, rax
    adc rcx, rdx
    ; t0 in rcx:rbx, take low 51 bits for limb[0]
    mov rdi, rbx
    and rdi, [mask51_val]
    mov [r12], rdi
    ; carry = t0 >> 51
    shrd rbx, rcx, 51
    shr rcx, 51
    ; carry in rbx (rcx should be 0 for normal inputs)

    ; t1 = a0*b1 + a1*b0 + a2*b4_19 + a3*b3_19 + a4*b2_19 + carry
    mov rax, r8
    mul qword [rbp - 80]    ; a0*b1
    add rbx, rax
    adc rcx, rdx

    mov rax, r9
    mul qword [rbp - 88]    ; a1*b0
    add rbx, rax
    adc rcx, rdx

    mov rax, r10
    mul qword [rbp - 24]    ; a2*b4_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r11
    mul qword [rbp - 32]    ; a3*b3_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r15
    mul qword [rbp - 40]    ; a4*b2_19
    add rbx, rax
    adc rcx, rdx

    mov rdi, rbx
    and rdi, [mask51_val]
    mov [r12 + 8], rdi
    shrd rbx, rcx, 51
    shr rcx, 51

    ; t2 = a0*b2 + a1*b1 + a2*b0 + a3*b4_19 + a4*b3_19 + carry
    mov rax, r8
    mul qword [rbp - 72]    ; a0*b2
    add rbx, rax
    adc rcx, rdx

    mov rax, r9
    mul qword [rbp - 80]    ; a1*b1
    add rbx, rax
    adc rcx, rdx

    mov rax, r10
    mul qword [rbp - 88]    ; a2*b0
    add rbx, rax
    adc rcx, rdx

    mov rax, r11
    mul qword [rbp - 24]    ; a3*b4_19
    add rbx, rax
    adc rcx, rdx

    mov rax, r15
    mul qword [rbp - 32]    ; a4*b3_19
    add rbx, rax
    adc rcx, rdx

    mov rdi, rbx
    and rdi, [mask51_val]
    mov [r12 + 16], rdi
    shrd rbx, rcx, 51
    shr rcx, 51

    ; t3 = a0*b3 + a1*b2 + a2*b1 + a3*b0 + a4*b4_19 + carry
    mov rax, r8
    mul qword [rbp - 64]    ; a0*b3
    add rbx, rax
    adc rcx, rdx

    mov rax, r9
    mul qword [rbp - 72]    ; a1*b2
    add rbx, rax
    adc rcx, rdx

    mov rax, r10
    mul qword [rbp - 80]    ; a2*b1
    add rbx, rax
    adc rcx, rdx

    mov rax, r11
    mul qword [rbp - 88]    ; a3*b0
    add rbx, rax
    adc rcx, rdx

    mov rax, r15
    mul qword [rbp - 24]    ; a4*b4_19
    add rbx, rax
    adc rcx, rdx

    mov rdi, rbx
    and rdi, [mask51_val]
    mov [r12 + 24], rdi
    shrd rbx, rcx, 51
    shr rcx, 51

    ; t4 = a0*b4 + a1*b3 + a2*b2 + a3*b1 + a4*b0 + carry
    mov rax, r8
    mul qword [rbp - 56]    ; a0*b4
    add rbx, rax
    adc rcx, rdx

    mov rax, r9
    mul qword [rbp - 64]    ; a1*b3
    add rbx, rax
    adc rcx, rdx

    mov rax, r10
    mul qword [rbp - 72]    ; a2*b2
    add rbx, rax
    adc rcx, rdx

    mov rax, r11
    mul qword [rbp - 80]    ; a3*b1
    add rbx, rax
    adc rcx, rdx

    mov rax, r15
    mul qword [rbp - 88]    ; a4*b0
    add rbx, rax
    adc rcx, rdx

    mov rdi, rbx
    and rdi, [mask51_val]
    mov [r12 + 32], rdi
    shrd rbx, rcx, 51
    ; Top carry wraps: multiply by 19 and add to limb[0]
    imul rbx, 19
    add [r12], rbx

    ; Final carry propagation
    mov rax, [r12]
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [r12], rax
    add [r12 + 8], rbx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 88
    pop rbp
    ret

; fe_sq(r, a)
; r = a^2 mod p (optimized squaring)
; rdi=r, rsi=a
global _fe_sq
_fe_sq:
    mov rdx, rsi
    jmp _fe_mul             ; For now, just use mul(r, a, a)

; fe_reduce(a)
; Fully reduce a to canonical form [0, p)
; rdi=a
global _fe_reduce
_fe_reduce:
    push rbx

    ; First pass: carry propagation
    mov rax, [rdi]
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi], rax

    mov rax, [rdi + 8]
    add rax, rbx
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi + 8], rax

    mov rax, [rdi + 16]
    add rax, rbx
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi + 16], rax

    mov rax, [rdi + 24]
    add rax, rbx
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi + 24], rax

    mov rax, [rdi + 32]
    add rax, rbx
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi + 32], rax

    ; Wrap top carry: multiply by 19 and add to limb[0]
    imul rbx, 19
    add [rdi], rbx

    ; Second pass for potential carry from the *19 add
    mov rax, [rdi]
    mov rbx, rax
    shr rbx, 51
    and rax, [mask51_val]
    mov [rdi], rax
    add [rdi + 8], rbx

    ; Conditional subtraction of p if >= p
    ; Check if all limbs match p or exceed
    ; p = (2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1)
    ; If limb[4] > MASK51 impossible after reduce
    ; If all limbs == p limbs, subtract p
    ; If limb[4] == MASK51 and limb[3] == MASK51 and ... and limb[0] >= 2^51-19
    mov rax, [rdi + 32]
    cmp rax, [mask51_val]
    jb .done
    mov rax, [rdi + 24]
    cmp rax, [mask51_val]
    jb .done
    mov rax, [rdi + 16]
    cmp rax, [mask51_val]
    jb .done
    mov rax, [rdi + 8]
    cmp rax, [mask51_val]
    jb .done
    mov rax, [rdi]
    cmp rax, [p0_val]              ; 2^51 - 19
    jb .done

    ; Subtract p (need register since sub [mem], imm64 not supported)
    mov rax, [p0_val]
    sub [rdi], rax
    mov rax, [mask51_val]
    sub [rdi + 8], rax
    sub [rdi + 16], rax
    sub [rdi + 24], rax
    sub [rdi + 32], rax

.done:
    pop rbx
    ret

; fe_tobytes(out, a)
; Serialize field element to 32 bytes little-endian
; rdi=out (32 bytes), rsi=a (5 limbs)
global _fe_tobytes
_fe_tobytes:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi            ; out
    mov r13, rsi            ; a

    ; First fully reduce
    mov rdi, r13
    call _fe_reduce

    ; Load reduced limbs
    mov rax, [r13]          ; l0 (bits 0-50)
    mov rbx, [r13 + 8]      ; l1 (bits 51-101)
    mov rcx, [r13 + 16]     ; l2 (bits 102-152)
    mov r8, [r13 + 24]      ; l3 (bits 153-203)
    mov r9, [r13 + 32]      ; l4 (bits 204-254)

    ; Pack into 256 bits (32 bytes), little-endian
    ; Byte 0-7: bits 0-63 = l0[0:51] | l1[0:12] << 51
    mov rdx, rbx
    shl rdx, 51
    or rax, rdx
    mov [r12], rax

    ; Byte 8-15: bits 64-127 = l1[13:51] | l2[0:25] << 38
    mov rax, rbx
    shr rax, 13
    mov rdx, rcx
    shl rdx, 38
    or rax, rdx
    mov [r12 + 8], rax

    ; Byte 16-23: bits 128-191 = l2[26:51] | l3[0:38] << 25
    mov rax, rcx
    shr rax, 26
    mov rdx, r8
    shl rdx, 25
    or rax, rdx
    mov [r12 + 16], rax

    ; Byte 24-31: bits 192-255 = l3[39:51] | l4[0:51] << 12
    mov rax, r8
    shr rax, 39
    mov rdx, r9
    shl rdx, 12
    or rax, rdx
    mov [r12 + 24], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; fe_frombytes(r, in)
; Deserialize 32 bytes little-endian to field element
; rdi=r (5 limbs), rsi=in (32 bytes)
global _fe_frombytes
_fe_frombytes:
    ; Load 4 x 64-bit words from input
    mov rax, [rsi]          ; bits 0-63
    mov rcx, [rsi + 8]      ; bits 64-127
    mov r8, [rsi + 16]      ; bits 128-191
    mov r9, [rsi + 24]      ; bits 192-255

    ; l0 = bits[0:50]
    mov rdx, rax
    and rdx, [mask51_val]
    mov [rdi], rdx

    ; l1 = bits[51:101]
    mov rdx, rax
    shr rdx, 51
    mov r10, rcx
    shl r10, 13
    or rdx, r10
    and rdx, [mask51_val]
    mov [rdi + 8], rdx

    ; l2 = bits[102:152]
    mov rdx, rcx
    shr rdx, 38
    mov r10, r8
    shl r10, 26
    or rdx, r10
    and rdx, [mask51_val]
    mov [rdi + 16], rdx

    ; l3 = bits[153:203]
    mov rdx, r8
    shr rdx, 25
    mov r10, r9
    shl r10, 39
    or rdx, r10
    and rdx, [mask51_val]
    mov [rdi + 24], rdx

    ; l4 = bits[204:254] (top bit cleared for Curve25519)
    mov rdx, r9
    shr rdx, 12
    and rdx, [mask51_val]
    mov [rdi + 32], rdx
    ret

; fe_inv(r, a)
; r = a^(-1) mod p using Fermat's little theorem: a^(p-2) mod p
; p-2 = 2^255 - 21
; Uses addition chain for efficiency
; rdi=r, rsi=a
global _fe_inv
_fe_inv:
    push rbp
    mov rbp, rsp
    ; Need several temp field elements: t0, t1, t2, t3
    ; Each 40 bytes, need 4 + save input = 200 + some alignment
    sub rsp, 320            ; generous stack
    push rbx
    push r12
    push r13

    mov r12, rdi            ; result
    mov r13, rsi            ; input a

    ; t0 at [rbp-40], t1 at [rbp-80], t2 at [rbp-120], t3 at [rbp-160]
    %define T0 rbp-40
    %define T1 rbp-80
    %define T2 rbp-120
    %define T3 rbp-160

    ; z2 = z^2
    lea rdi, [T0]
    mov rsi, r13
    mov rdx, r13
    call _fe_mul

    ; z9 = z2^4 * z = ((z2^2)^2) * z
    ; z4 = z2^2
    lea rdi, [T1]
    lea rsi, [T0]
    lea rdx, [T0]
    call _fe_mul

    ; z8 = z4^2
    lea rdi, [T1]
    lea rsi, [T1]
    lea rdx, [T1]
    call _fe_mul

    ; z9 = z8 * z
    lea rdi, [T1]
    lea rsi, [T1]
    mov rdx, r13
    call _fe_mul

    ; z11 = z9 * z2
    lea rdi, [T2]
    lea rsi, [T1]
    lea rdx, [T0]
    call _fe_mul

    ; z_5_0 = z11^2 * z9
    lea rdi, [T0]
    lea rsi, [T2]
    lea rdx, [T2]
    call _fe_mul
    lea rdi, [T0]
    lea rsi, [T0]
    lea rdx, [T1]
    call _fe_mul

    ; z_10_0 = z_5_0^(2^5) * z_5_0
    lea rdi, [T1]
    lea rsi, [T0]
    lea rdx, [T0]
    call _fe_mul
    ; Square 4 more times
    mov ecx, 4
.sq10:
    push rcx
    lea rdi, [T1]
    lea rsi, [T1]
    lea rdx, [T1]
    call _fe_mul
    pop rcx
    dec ecx
    jnz .sq10

    lea rdi, [T1]
    lea rsi, [T1]
    lea rdx, [T0]
    call _fe_mul

    ; z_20_0 = z_10_0^(2^10) * z_10_0
    lea rdi, [T3]
    lea rsi, [T1]
    lea rdx, [T1]
    call _fe_mul
    mov ecx, 9
.sq20:
    push rcx
    lea rdi, [T3]
    lea rsi, [T3]
    lea rdx, [T3]
    call _fe_mul
    pop rcx
    dec ecx
    jnz .sq20

    lea rdi, [T3]
    lea rsi, [T3]
    lea rdx, [T1]
    call _fe_mul

    ; z_40_0 = z_20_0^(2^20) * z_20_0
    lea rdi, [T3]
    lea rsi, [T3]
    lea rdx, [T3]
    ; First square 20 times
    mov ecx, 20
.sq40:
    push rcx
    lea rdi, [T3]
    lea rsi, [T3]
    lea rdx, [T3]
    call _fe_mul
    pop rcx
    dec ecx
    jnz .sq40

    ; Now we need z_20_0 but it was overwritten... let's redo this more carefully
    ; Actually, let me use a simpler approach: repeated squaring with known exponent

    ; Simpler approach: compute a^(p-2) by repeated square-and-multiply
    ; p - 2 = 2^255 - 21 = 2^255 - 16 - 4 - 1
    ;       = all 1 bits from 254 down to 5, then 01011
    ;
    ; Bits of p-2 (from high to low, 254 down to 0):
    ; 254..5: all 1 (250 ones)
    ; 4: 0
    ; 3: 1
    ; 2: 0
    ; 1: 1
    ; 0: 1
    ;
    ; Use simple square-and-multiply

    ; Start with result = a (bit 254 = 1)
    mov rdi, r12
    mov rsi, r13
    call _fe_copy

    ; Process bits 253 down to 0
    mov ecx, 253
.exp_loop:
    push rcx

    ; Square
    lea rdi, [T0]
    mov rsi, r12
    mov rdx, r12
    call _fe_mul
    ; Copy T0 -> result
    mov rdi, r12
    lea rsi, [T0]
    call _fe_copy

    pop rcx

    ; Check if bit ecx of (p-2) is set
    ; p-2 = 2^255 - 21
    ; All bits 254..5 are set, bit 4 clear, bit 3 set, bit 2 clear, bits 1,0 set
    cmp ecx, 5
    jge .bit_set              ; bits 254..5 all set
    ; Bits 4..0: pattern is 01011 = bit4=0, bit3=1, bit2=0, bit1=1, bit0=1
    cmp ecx, 3
    je .bit_set
    cmp ecx, 1
    je .bit_set
    cmp ecx, 0
    je .bit_set
    jmp .bit_clear

.bit_set:
    push rcx
    ; Multiply by a
    lea rdi, [T0]
    mov rsi, r12
    mov rdx, r13
    call _fe_mul
    mov rdi, r12
    lea rsi, [T0]
    call _fe_copy
    pop rcx

.bit_clear:
    dec ecx
    jns .exp_loop

    pop r13
    pop r12
    pop rbx
    add rsp, 320
    pop rbp
    ret

; fe_cswap(a, b, swap)
; Constant-time swap of two field elements
; rdi=a, rsi=b, edx=swap (0 or 1)
global _fe_cswap
_fe_cswap:
    neg edx                 ; 0 -> 0, 1 -> 0xFFFFFFFF
    movsxd rdx, edx         ; sign extend to 64-bit mask

    ; For each limb
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

    mov rax, [rdi + 32]
    mov rcx, [rsi + 32]
    mov r8, rax
    xor r8, rcx
    and r8, rdx
    xor rax, r8
    xor rcx, r8
    mov [rdi + 32], rax
    mov [rsi + 32], rcx
    ret

; fe_neg(r, a)
; r = -a mod p = p - a
; rdi=r, rsi=a
global _fe_neg
_fe_neg:
    push rbx
    ; r = p - a
    lea rdx, [fe_p]

    mov rax, [rdx]
    sub rax, [rsi]
    mov [rdi], rax

    mov rax, [rdx + 8]
    sbb rax, [rsi + 8]
    mov [rdi + 8], rax

    mov rax, [rdx + 16]
    sbb rax, [rsi + 16]
    mov [rdi + 16], rax

    mov rax, [rdx + 24]
    sbb rax, [rsi + 24]
    mov [rdi + 24], rax

    mov rax, [rdx + 32]
    sbb rax, [rsi + 32]
    mov [rdi + 32], rax

    ; Carry propagation (handle borrow)
    mov rax, [rdi]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi], rax
    add [rdi + 8], rbx

    mov rax, [rdi + 8]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 8], rax
    add [rdi + 16], rbx

    mov rax, [rdi + 16]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 16], rax
    add [rdi + 24], rbx

    mov rax, [rdi + 24]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 24], rax
    add [rdi + 32], rbx

    mov rax, [rdi + 32]
    mov rbx, rax
    sar rbx, 51
    and rax, [mask51_val]
    mov [rdi + 32], rax
    imul rbx, 19
    add [rdi], rbx

    pop rbx
    ret

; fe_mul121666(r, a)
; r = a * 121665 mod p (a24 = (486662-2)/4 for Curve25519 Montgomery ladder)
; NOTE: named "mul121666" for historical reasons, actually multiplies by 121665
;
; Uses 51-bit carry propagation (not 64-bit) since limbs are radix-2^51.
; Each limb product is split at the 51-bit boundary via shrd.
; rdi=r, rsi=a
global _fe_mul121666
_fe_mul121666:
    push rbx
    push r12

    mov r12, rdi            ; save output pointer (rdi clobbered as temp)
    mov ecx, 121665
    xor ebx, ebx            ; carry = 0

    ; limb[0]
    mov rax, [rsi]
    mul rcx                 ; rdx:rax = limb[0] * 121665
    ; carry is 0, skip add
    mov rdi, rax
    and rdi, [mask51_val]   ; result[0] = bottom 51 bits
    mov [r12], rdi
    shrd rax, rdx, 51       ; carry = (rdx:rax) >> 51
    mov rbx, rax

    ; limb[1]
    mov rax, [rsi + 8]
    mul rcx
    add rax, rbx
    adc rdx, 0
    mov rdi, rax
    and rdi, [mask51_val]
    mov [r12 + 8], rdi
    shrd rax, rdx, 51
    mov rbx, rax

    ; limb[2]
    mov rax, [rsi + 16]
    mul rcx
    add rax, rbx
    adc rdx, 0
    mov rdi, rax
    and rdi, [mask51_val]
    mov [r12 + 16], rdi
    shrd rax, rdx, 51
    mov rbx, rax

    ; limb[3]
    mov rax, [rsi + 24]
    mul rcx
    add rax, rbx
    adc rdx, 0
    mov rdi, rax
    and rdi, [mask51_val]
    mov [r12 + 24], rdi
    shrd rax, rdx, 51
    mov rbx, rax

    ; limb[4]
    mov rax, [rsi + 32]
    mul rcx
    add rax, rbx
    adc rdx, 0
    mov rdi, rax
    and rdi, [mask51_val]
    mov [r12 + 32], rdi
    shrd rax, rdx, 51
    mov rbx, rax

    ; Top carry wraps: multiply by 19 and add to limb[0]
    imul rbx, 19
    add [r12], rbx

    pop r12
    pop rbx
    ret
