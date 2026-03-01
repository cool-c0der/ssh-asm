; =============================================================================
; poly1305.asm — Poly1305 MAC (RFC 8439)
;
; Uses 3-limb representation: h = h0 + h1*2^64 + h2*2^128
; h2 has at most 5 bits after each reduction
; r = r0 + r1*2^64 (128 bits, clamped)
;
; For each 16-byte block:
;   h += block (with hibit)
;   h = (h * r) mod (2^130 - 5)
; Final: tag = (h + s) mod 2^128
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

; poly1305_mac(key, msg, msg_len, tag)
; rdi = 32-byte key (r[0..15] || s[0..15])
; rsi = message
; rdx = message length
; rcx = 16-byte output tag
global _poly1305_mac
_poly1305_mac:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; Save arguments
    mov r12, rsi             ; msg
    mov r13, rdx             ; msg_len
    mov r14, rcx             ; tag output

    ; Load and clamp r
    mov rax, [rdi]           ; r low 8 bytes
    mov rdx, [rdi + 8]       ; r high 8 bytes
    ; Clamp: r &= 0x0ffffffc0ffffffc_0ffffffc0fffffff
    ; x86_64 AND only accepts sign-extended 32-bit imm, so use register
    mov r8, 0x0ffffffc0fffffff
    and rax, r8
    mov r8, 0x0ffffffc0ffffffc
    and rdx, r8
    ; Store r0, r1 on stack
    push rdx                 ; [rsp+8] = r1 (after next push)
    push rax                 ; [rsp+0] = r0

    ; Load s
    mov r8, [rdi + 16]       ; s low
    mov r9, [rdi + 24]       ; s high
    push r9                  ; [rsp+16] = s1
    push r8                  ; [rsp+8] = s0

    ; Stack: [rsp]=s0, [rsp+8]=s1, [rsp+16]=r0, [rsp+24]=r1

    ; Initialize accumulator h = 0
    xor r15d, r15d           ; h0 = 0
    xor ebx, ebx             ; h1 = 0
    xor ecx, ecx             ; h2 = 0

    ; Process 16-byte blocks
.block_loop:
    cmp r13, 0
    jle .finalize

    ; --- Load message block into (n0, n1) with hibit ---
    sub rsp, 32              ; temp space
    ; Stack: [rsp]=n0(8), [rsp+8]=n1(8), [rsp+16]=hibit(8), [rsp+24]=block_size(8)
    ; Outer: [rsp+32]=s0, [rsp+40]=s1, [rsp+48]=r0, [rsp+56]=r1

    ; Determine block size
    mov rax, 16
    cmp r13, 16
    cmovb rax, r13
    mov [rsp + 24], rax      ; save block_size

    ; Zero block accumulators
    mov qword [rsp], 0       ; n0
    mov qword [rsp + 8], 0   ; n1
    mov qword [rsp + 16], 0  ; hibit

    ; Simple byte-by-byte load into n0/n1 (LE native on x86)
    ; Save h2 (ecx) to r10d temporarily — will restore after block load
    mov r10d, ecx
    xor esi, esi             ; byte index
.load_byte:
    cmp rsi, rax
    jge .load_done
    movzx edi, byte [r12 + rsi]
    mov r8, rdi
    cmp esi, 8
    jge .byte_to_n1
    ; Byte goes into n0
    mov ecx, esi
    shl ecx, 3
    shl r8, cl
    or [rsp], r8
    inc rsi
    jmp .load_byte
.byte_to_n1:
    mov ecx, esi
    sub ecx, 8
    shl ecx, 3
    shl r8, cl
    or [rsp + 8], r8
    inc rsi
    jmp .load_byte
.load_done:
    mov ecx, r10d            ; restore h2

.add_hibit:
    ; Set the hibit: bit at position (block_size * 8)
    ; MUST NOT clobber ecx (h2)!
    mov rax, [rsp + 24]     ; block_size
    mov edx, eax
    shl edx, 3              ; bit position

    cmp edx, 128
    jge .hibit_at_128
    cmp edx, 64
    jge .hibit_at_high

    ; Hibit in n0 (block_size < 8): set bit edx in [rsp]
    movzx eax, dl           ; bit position (0-63)
    bts qword [rsp], rax
    jmp .do_accumulate

.hibit_at_high:
    ; Hibit in n1 (8 <= block_size < 16): set bit (edx-64) in [rsp+8]
    sub edx, 64
    movzx eax, dl
    bts qword [rsp + 8], rax
    jmp .do_accumulate

.hibit_at_128:
    ; block_size = 16: hibit at bit 128 → goes into h2
    mov byte [rsp + 16], 1

.do_accumulate:
    ; h += block: h0 += n0, h1 += n1 (with carry), h2 += hibit_carry
    add r15, [rsp]           ; h0 += n0
    adc rbx, [rsp + 8]      ; h1 += n1
    movzx eax, byte [rsp + 16]
    adc ecx, eax             ; h2 += hibit (ecx was h2)

    ; --- h = (h * r) mod (2^130 - 5) ---
    ; h = (h0=r15, h1=rbx, h2=ecx)
    ; r = (r0=[rsp+48], r1=[rsp+56])

    ; We compute the product using mul:
    ; Product = h0*r0 + (h0*r1 + h1*r0)*2^64 + (h1*r1 + h2*r0)*2^128 + h2*r1*2^192
    ;
    ; We collect into 5 64-bit words: t0, t1, t2, t3, t4

    ; Save h2 since we'll clobber rcx
    mov r10d, ecx            ; r10d = h2

    ; d0 = h0 * r0
    mov rax, r15
    mul qword [rsp + 48]     ; rdx:rax = h0 * r0
    mov r8, rax              ; t0 = low
    mov r9, rdx              ; carry0 = high

    ; d1_part1 = h0 * r1
    mov rax, r15
    mul qword [rsp + 56]     ; rdx:rax = h0 * r1
    add r9, rax              ; t1 += low(h0*r1)
    mov r11, rdx             ; carry
    adc r11, 0

    ; d1_part2 = h1 * r0
    mov rax, rbx
    mul qword [rsp + 48]     ; rdx:rax = h1 * r0
    add r9, rax              ; t1 += low(h1*r0)
    adc r11, rdx             ; carry1 += high(h1*r0)
    mov rdi, 0
    adc rdi, 0               ; extra carry

    ; t0 = r8, t1 = r9
    ; carry going into t2: r11 + rdi flag

    ; d2_part1 = h1 * r1
    mov rax, rbx
    mul qword [rsp + 56]     ; rdx:rax = h1 * r1
    add r11, rax             ; t2 += low(h1*r1)
    adc rdi, rdx             ; carry

    ; d2_part2 = h2 * r0
    movzx eax, r10b          ; h2 (small, fits in 32 bits)
    mul qword [rsp + 48]     ; rdx:rax = h2 * r0
    add r11, rax             ; t2 += low(h2*r0)
    adc rdi, rdx

    ; d3 = h2 * r1
    movzx eax, r10b
    mul qword [rsp + 56]     ; rdx:rax = h2 * r1
    add rdi, rax             ; t3 += low(h2*r1)
    mov rsi, rdx
    adc rsi, 0               ; t4

    ; Product is: t0(r8) + t1(r9)*2^64 + t2(r11)*2^128 + t3(rdi)*2^192 + t4(rsi)*2^256

    ; --- Reduce mod 2^130 - 5 ---
    ; Split at bit 130:
    ; lower = t0 + t1*2^64 + (t2 & 3)*2^128
    ; upper_at_bit_0 = (t2 >> 2) + t3*2^62 + t4*2^126 (... but upper * 5 is added to lower)
    ;
    ; More precisely: upper * 5 is what we add.
    ; Since 2^130 ≡ 5 (mod p), bits above 130 get multiplied by 5.

    ; Extract lower 130 bits
    mov r15, r8              ; h0 = t0
    mov rbx, r9              ; h1 = t1
    mov ecx, r11d
    and ecx, 3               ; h2 = t2 & 3

    ; Upper part starting at bit 130
    ; u0 = (t2 >> 2) | (t3 << 62)
    ; u1 = (t3 >> 2) | (t4 << 62)
    ; u2 = (t4 >> 2)
    shrd r11, rdi, 2         ; u0
    shrd rdi, rsi, 2         ; u1
    shr rsi, 2               ; u2

    ; h += upper * 5
    mov rax, r11
    mov rdx, 5
    mul rdx                  ; rdx:rax = u0 * 5
    add r15, rax
    adc rbx, rdx
    adc ecx, 0

    mov rax, rdi
    mov rdx, 5
    mul rdx                  ; rdx:rax = u1 * 5
    add rbx, rax
    adc ecx, edx

    ; u2 * 5 (u2 should be very small or 0)
    imul eax, esi, 5
    add ecx, eax

    ; Move to next block
    mov rax, [rsp + 24]      ; block_size
    add r12, rax
    sub r13, rax
    add rsp, 32

    jmp .block_loop

.finalize:
    ; h is in (r15, rbx, ecx)
    ; Final reduction: ensure h < p = 2^130 - 5
    ; Compute g = h + 5, check if g >= 2^130
    mov r8, r15
    add r8, 5
    mov r9, rbx
    adc r9, 0
    mov r10d, ecx
    adc r10d, 0

    ; If bit 130 of g is set (r10d >= 4), then h >= p, use g - 2^130
    bt r10d, 2               ; test bit 2 (which is bit 130 overall)
    jnc .no_reduce

    ; h >= p, use g with bit 130+ cleared
    and r10d, 3
    mov r15, r8
    mov rbx, r9
    mov ecx, r10d
.no_reduce:

    ; tag = (h + s) mod 2^128 (drop h2 and any carry)
    add r15, [rsp]           ; h0 + s0
    adc rbx, [rsp + 8]       ; h1 + s1

    ; Write tag (little-endian 16 bytes)
    mov [r14], r15
    mov [r14 + 8], rbx

    ; Clean up stack (s0, s1, r0, r1 = 32 bytes)
    add rsp, 32

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
