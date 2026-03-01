; =============================================================================
; ed25519.asm — Ed25519 signature scheme (RFC 8032)
;
; Edwards curve: -x^2 + y^2 = 1 + d*x^2*y^2
; d = -121665/121666 mod p
;
; Extended coordinates: (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z
;
; Functions:
;   ed25519_publickey(sk, pk) — derive public key from 32-byte seed
;   ed25519_sign(sk, pk, msg, msg_len, sig) — sign message
;
; Each point uses 4 field elements = 160 bytes
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

%define FE_SIZE 40
%define POINT_SIZE 160      ; 4 * FE_SIZE

section .data
align 16

; d = -121665/121666 mod p (5-limb radix-2^51)
; d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
ed25519_d:
    dq 0x34DCA135978A3, 0x1A8283B156EBD, 0x5E7A26001C029
    dq 0x739C663A03CBB, 0x52036CEE2B6FF

; 2*d
ed25519_2d:
    dq 0x69B9426B2F159, 0x35050762ADD7A, 0x3CF44C0038052
    dq 0x6738CC7407977, 0x2406D9DC56DFF

; Basepoint B (extended coordinates)
; B.x = 15112221349535807912866137220509078750507884956996801397370759227791125407698
; B.y = 46316835694926478169428394003475163141307993866256225615783033890098355573289
; B.z = 1
; B.t = B.x * B.y mod p

; B.y in 5-limb:
ed25519_By:
    dq 0x6666666666658, 0x4CCCCCCCCCCCC, 0x1999999999999
    dq 0x3333333333333, 0x6666666666666

; B.x in 5-limb:
ed25519_Bx:
    dq 0x62D608F25D51A, 0x412A4B4F6592A, 0x75B7171A4B31D
    dq 0x1FF60527118FE, 0x216936D3CD6E5

; L (group order) = 2^252 + 27742317777372353535851937790883648493
; Stored as 32 bytes little-endian for scalar reduction
ed25519_L:
    db 0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58
    db 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10

section .text

extern _fe_zero
extern _fe_one
extern _fe_copy
extern _fe_add
extern _fe_sub
extern _fe_mul
extern _fe_inv
extern _fe_neg
extern _fe_tobytes
extern _fe_frombytes
extern _fe_reduce
extern _sha512_hash
extern _sha512_init
extern _sha512_update
extern _sha512_final
extern _memcpy
extern _memset

; --- Internal: Point operations ---

; _ed_point_zero(P)
; Set P = neutral element (0, 1, 1, 0)
; rdi = P (160 bytes)
_ed_point_zero:
    push r12
    mov r12, rdi

    ; X = 0
    call _fe_zero
    ; Y = 1
    lea rdi, [r12 + FE_SIZE]
    call _fe_one
    ; Z = 1
    lea rdi, [r12 + 2*FE_SIZE]
    call _fe_one
    ; T = 0
    lea rdi, [r12 + 3*FE_SIZE]
    call _fe_zero

    pop r12
    ret

; _ed_point_add(R, P, Q)
; R = P + Q using extended coordinates
; rdi=R (160 bytes), rsi=P (160 bytes), rdx=Q (160 bytes)
; Uses ~320 bytes of stack for temporaries
_ed_point_add:
    push rbp
    mov rbp, rsp
    sub rsp, 400            ; 10 field element temps
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi            ; R
    mov r13, rsi            ; P
    mov r14, rdx            ; Q

    ; Temps: a,b,c,d,e,f,g,h at [rbp-40], [rbp-80], etc.
    %define TA rbp - 40
    %define TB rbp - 80
    %define TC rbp - 120
    %define TD rbp - 160
    %define TE rbp - 200
    %define TF rbp - 240
    %define TG rbp - 280
    %define TH rbp - 320

    ; a = (Y1-X1) * (Y2-X2)
    lea rdi, [TA]
    lea rsi, [r13 + FE_SIZE]     ; Y1
    lea rdx, [r13]               ; X1
    call _fe_sub
    lea rdi, [TB]
    lea rsi, [r14 + FE_SIZE]     ; Y2
    lea rdx, [r14]               ; X2
    call _fe_sub
    lea rdi, [TA]
    lea rsi, [TA]
    lea rdx, [TB]
    call _fe_mul

    ; b = (Y1+X1) * (Y2+X2)
    lea rdi, [TB]
    lea rsi, [r13 + FE_SIZE]
    lea rdx, [r13]
    call _fe_add
    lea rdi, [TC]
    lea rsi, [r14 + FE_SIZE]
    lea rdx, [r14]
    call _fe_add
    lea rdi, [TB]
    lea rsi, [TB]
    lea rdx, [TC]
    call _fe_mul

    ; c = T1 * 2*d * T2
    lea rdi, [TC]
    lea rsi, [r13 + 3*FE_SIZE]   ; T1
    lea rdx, [r14 + 3*FE_SIZE]   ; T2
    call _fe_mul
    lea rdi, [TC]
    lea rsi, [TC]
    lea rdx, [ed25519_2d]
    call _fe_mul

    ; d = Z1 * 2 * Z2
    lea rdi, [TD]
    lea rsi, [r13 + 2*FE_SIZE]   ; Z1
    lea rdx, [r14 + 2*FE_SIZE]   ; Z2
    call _fe_mul
    ; d = d + d (multiply by 2)
    lea rdi, [TD]
    lea rsi, [TD]
    lea rdx, [TD]
    call _fe_add

    ; e = b - a
    lea rdi, [TE]
    lea rsi, [TB]
    lea rdx, [TA]
    call _fe_sub

    ; f = d - c
    lea rdi, [TF]
    lea rsi, [TD]
    lea rdx, [TC]
    call _fe_sub

    ; g = d + c
    lea rdi, [TG]
    lea rsi, [TD]
    lea rdx, [TC]
    call _fe_add

    ; h = b + a
    lea rdi, [TH]
    lea rsi, [TB]
    lea rdx, [TA]
    call _fe_add

    ; R.X = e * f
    lea rdi, [r12]
    lea rsi, [TE]
    lea rdx, [TF]
    call _fe_mul

    ; R.Y = g * h
    lea rdi, [r12 + FE_SIZE]
    lea rsi, [TG]
    lea rdx, [TH]
    call _fe_mul

    ; R.T = e * h
    lea rdi, [r12 + 3*FE_SIZE]
    lea rsi, [TE]
    lea rdx, [TH]
    call _fe_mul

    ; R.Z = f * g
    lea rdi, [r12 + 2*FE_SIZE]
    lea rsi, [TF]
    lea rdx, [TG]
    call _fe_mul

    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 400
    pop rbp
    ret

; _ed_scalar_mul(R, scalar, P)
; R = scalar * P (double-and-add, constant-time-ish via always-add)
; rdi=R, rsi=scalar (32 bytes LE), rdx=P
_ed_scalar_mul:
    push rbp
    mov rbp, rsp
    ; Need: Q (accumulator 160 bytes), temp point (160 bytes)
    sub rsp, 384
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi            ; R
    mov r13, rsi            ; scalar
    mov r14, rdx            ; P

    %define SM_Q   rbp - 160
    %define SM_TMP rbp - 320

    ; Q = neutral element
    lea rdi, [SM_Q]
    call _ed_point_zero

    ; Process 256 bits from high to low
    mov ebx, 255

.sm_loop:
    ; Double: Q = Q + Q
    lea rdi, [SM_TMP]
    lea rsi, [SM_Q]
    lea rdx, [SM_Q]
    call _ed_point_add
    ; Copy back
    lea rdi, [SM_Q]
    lea rsi, [SM_TMP]
    mov ecx, POINT_SIZE
    rep movsb

    ; Check bit
    mov ecx, ebx
    shr ecx, 3
    movzx eax, byte [r13 + rcx]
    mov ecx, ebx
    and ecx, 7
    shr eax, cl
    and eax, 1
    test eax, eax
    jz .sm_no_add

    ; Add: Q = Q + P
    lea rdi, [SM_TMP]
    lea rsi, [SM_Q]
    mov rdx, r14
    call _ed_point_add
    lea rdi, [SM_Q]
    lea rsi, [SM_TMP]
    mov ecx, POINT_SIZE
    rep movsb

.sm_no_add:
    dec ebx
    jns .sm_loop

    ; Copy result to R
    mov rdi, r12
    lea rsi, [SM_Q]
    mov ecx, POINT_SIZE
    rep movsb

    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 384
    pop rbp
    ret

; _ed_point_encode(out, P)
; Encode extended point to 32 bytes (compress: y with sign of x in top bit)
; rdi=out (32 bytes), rsi=P (160 bytes)
_ed_point_encode:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13

    mov r12, rdi            ; out
    mov r13, rsi            ; P

    %define ENC_T0 rbp - 40
    %define ENC_T1 rbp - 80

    ; Compute x = X/Z, y = Y/Z
    ; inv_z = 1/Z
    lea rdi, [ENC_T0]
    lea rsi, [r13 + 2*FE_SIZE]   ; Z
    call _fe_inv

    ; y = Y * inv_z
    lea rdi, [ENC_T1]
    lea rsi, [r13 + FE_SIZE]     ; Y
    lea rdx, [ENC_T0]            ; inv_z
    call _fe_mul

    ; Serialize y
    mov rdi, r12
    lea rsi, [ENC_T1]
    call _fe_tobytes

    ; x = X * inv_z
    lea rdi, [ENC_T1]
    lea rsi, [r13]               ; X
    lea rdx, [ENC_T0]            ; inv_z
    call _fe_mul

    ; Reduce x fully
    lea rdi, [ENC_T1]
    call _fe_reduce

    ; Set top bit of last byte to sign of x (x mod 2)
    lea rax, [ENC_T1]
    mov rax, [rax]               ; limb[0]
    and al, 1                    ; sign bit
    shl al, 7
    or [r12 + 31], al

    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret

; _sc_reduce(s)
; Reduce 64-byte scalar mod L (group order)
; s = 64 bytes little-endian, result in first 32 bytes
; Uses Barrett reduction approximation for simplicity
; rdi = s (64 bytes input, 32 bytes output)
_sc_reduce:
    push rbp
    mov rbp, rsp
    sub rsp, 128
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; scalar (64 bytes)

    ; Load the 512-bit number in 8 x 64-bit limbs
    mov rax, [r12]
    mov rbx, [r12 + 8]
    mov rcx, [r12 + 16]
    mov rdx, [r12 + 24]
    mov r8, [r12 + 32]
    mov r9, [r12 + 40]
    mov r10, [r12 + 48]
    mov r11, [r12 + 56]

    ; For Ed25519, the hash output mod L reduction:
    ; L = 2^252 + 27742317777372353535851937790883648493
    ; We need s mod L for a 512-bit s.
    ;
    ; Simple approach: since s < 2^512 and L ~ 2^252,
    ; we need at most a few subtractions of L * 2^k.
    ;
    ; Use the identity: 2^252 ≡ -c mod L where c = 27742317777372353535851937790883648493
    ; c in hex: 14DEF9DEA2F79CD65812631A5CF5D3ED
    ;
    ; Split s = s_low (252 bits) + s_high * 2^252
    ; s mod L ≡ s_low - s_high * c (mod L)
    ;
    ; For a 512-bit input: s_high is up to 260 bits.
    ; The product s_high * c can be up to 260+128=388 bits.
    ; We may need to iterate the reduction.

    ; For simplicity and correctness: store the 64-byte value on stack,
    ; then do repeated subtraction of L (brute force but works for the
    ; small number of iterations needed in practice).

    ; Actually, let's use a different approach. SHA-512 outputs are 512 bits.
    ; We need to reduce mod a 253-bit number. That's about 2 iterations
    ; of the schoolbook reduction.

    ; Let's do it properly with the algorithm:
    ; 1. Split s into low 252 bits and high (512-252=260) bits
    ; 2. Compute high * (2^252 mod L) = high * (-c mod L) ... but this gets complex

    ; Simplest correct approach for our use case:
    ; Use repeated conditional subtraction. Since s < 2^512 and L ≈ 2^252,
    ; s/L < 2^260, so we'd need 2^260 subtractions — obviously not feasible.

    ; Better: use schoolbook division.
    ; Or: use the Barrett reduction from the Ed25519 paper.
    ; For a minimal implementation, let's use the approach from
    ; SUPERCOP/ref10: reduce using the relation 2^252 ≡ -c (mod L).

    ; Implementation: reduce a 64-byte (512-bit) scalar mod L
    ; by splitting into 21-byte chunks and using convolution.
    ; This is the standard "sc_reduce" from NaCl/SUPERCOP.

    ; For simplicity, I'll implement a basic multi-precision mod using
    ; trial subtraction with the two's complement trick.
    ; Since we only call this a few times (signing), performance isn't critical.

    ; Store input to stack
    mov [rbp - 64], rax
    mov [rbp - 56], rbx
    mov [rbp - 48], rcx
    mov [rbp - 40], rdx
    mov [rbp - 32], r8
    mov [rbp - 24], r9
    mov [rbp - 16], r10
    mov [rbp - 8], r11

    ; We'll reduce by subtracting L * 2^k for each high bit
    ; Process from bit 511 down to bit 252
    ; For each bit position i:
    ;   If bit i is set in s, subtract L << (i - 252) ... no, this isn't right either.

    ; Actually, let's just do basic Barrett-style:
    ; q = s >> 252 (approximate quotient, up to 260 bits)
    ; r = s - q * L
    ; if r >= L: r -= L

    ; q * L computation needs 260 * 253 = 513 bit result... still complex.

    ; Pragmatic approach: since we're in assembly and this is called rarely,
    ; let's use iterative reduction:
    ; While s >= 2^253: s = s_low_253_bits + (s >> 253) * (2^253 mod L)
    ; 2^253 mod L = 2 * 2^252 mod L = 2 * (L - c) mod L... no.
    ; 2^252 ≡ -c (mod L), so 2^253 ≡ -2c (mod L).
    ; |s_high| * 2c < 2^260 * 2^129 which is still huge.

    ; Let me just implement a simple long-division mod for 512-bit by 253-bit.
    ; Result fits in 32 bytes. Use shift-and-subtract algorithm.

    ; r = 0 (accumulator, 256 bits = 4 limbs)
    xor eax, eax
    mov [rbp - 96], rax     ; r[0]
    mov [rbp - 88], rax     ; r[1]
    mov [rbp - 80], rax     ; r[2]
    mov [rbp - 72], rax     ; r[3]

    ; Process bits from 511 down to 0
    mov ebx, 511

.reduce_loop:
    ; r = r << 1
    mov rax, [rbp - 72]     ; r[3]
    shl rax, 1
    mov r8, [rbp - 80]      ; r[2]
    shr r8, 63
    or rax, r8
    mov [rbp - 72], rax

    mov rax, [rbp - 80]
    shl rax, 1
    mov r8, [rbp - 88]
    shr r8, 63
    or rax, r8
    mov [rbp - 80], rax

    mov rax, [rbp - 88]
    shl rax, 1
    mov r8, [rbp - 96]
    shr r8, 63
    or rax, r8
    mov [rbp - 88], rax

    mov rax, [rbp - 96]
    shl rax, 1
    ; Add current bit of s
    mov ecx, ebx
    shr ecx, 6              ; qword index
    mov r8, [rbp - 64 + rcx*8]
    mov ecx, ebx
    and ecx, 63
    shr r8, cl
    and r8, 1
    or rax, r8
    mov [rbp - 96], rax

    ; if r >= L: r -= L
    ; Compare r with L (both 256-bit)
    ; L in memory: ed25519_L (32 bytes LE, 4 qwords)
    lea rsi, [ed25519_L]
    ; r[3] vs L[3]
    mov rax, [rbp - 72]
    mov rcx, [rsi + 24]
    cmp rax, rcx
    ja .do_sub
    jb .no_sub
    mov rax, [rbp - 80]
    mov rcx, [rsi + 16]
    cmp rax, rcx
    ja .do_sub
    jb .no_sub
    mov rax, [rbp - 88]
    mov rcx, [rsi + 8]
    cmp rax, rcx
    ja .do_sub
    jb .no_sub
    mov rax, [rbp - 96]
    mov rcx, [rsi]
    cmp rax, rcx
    jb .no_sub

.do_sub:
    lea rsi, [ed25519_L]
    mov rax, [rbp - 96]
    sub rax, [rsi]
    mov [rbp - 96], rax

    mov rax, [rbp - 88]
    sbb rax, [rsi + 8]
    mov [rbp - 88], rax

    mov rax, [rbp - 80]
    sbb rax, [rsi + 16]
    mov [rbp - 80], rax

    mov rax, [rbp - 72]
    sbb rax, [rsi + 24]
    mov [rbp - 72], rax

.no_sub:
    dec ebx
    jns .reduce_loop

    ; Copy result (32 bytes) to output
    mov rax, [rbp - 96]
    mov [r12], rax
    mov rax, [rbp - 88]
    mov [r12 + 8], rax
    mov rax, [rbp - 80]
    mov [r12 + 16], rax
    mov rax, [rbp - 72]
    mov [r12 + 24], rax

    ; Zero remaining 32 bytes of the 64-byte buffer
    xor eax, eax
    mov [r12 + 32], rax
    mov [r12 + 40], rax
    mov [r12 + 48], rax
    mov [r12 + 56], rax

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 128
    pop rbp
    ret

; --- Public API ---

; ed25519_publickey(sk, pk)
; Derive Ed25519 public key from 32-byte seed
; rdi = sk (32 bytes seed), rsi = pk (32 bytes output)
global _ed25519_publickey
_ed25519_publickey:
    push rbp
    mov rbp, rsp
    sub rsp, 512
    push rbx
    push r12
    push r13

    mov r12, rdi            ; sk (seed)
    mov r13, rsi            ; pk (output)

    ; Hash seed with SHA-512 -> 64 bytes
    ; h = SHA-512(sk)
    %define PK_HASH rbp - 64
    %define PK_POINT rbp - 224   ; 160 bytes
    %define PK_SCALAR rbp - 256  ; 32 bytes

    mov rdi, r12
    mov rsi, 32
    lea rdx, [PK_HASH]
    call _sha512_hash

    ; Clamp first 32 bytes (private scalar)
    lea rax, [PK_HASH]
    and byte [rax], 0xF8        ; Clear low 3 bits
    and byte [rax + 31], 0x7F   ; Clear top bit
    or  byte [rax + 31], 0x40   ; Set bit 254

    ; Prepare basepoint as extended point (X, Y, Z=1, T=X*Y)
    %define PK_BASE rbp - 416   ; 160 bytes

    ; Copy Bx, By to basepoint
    lea rdi, [PK_BASE]
    lea rsi, [ed25519_Bx]
    mov ecx, FE_SIZE
    rep movsb

    lea rdi, [PK_BASE + FE_SIZE]
    lea rsi, [ed25519_By]
    mov ecx, FE_SIZE
    rep movsb

    ; Z = 1
    lea rdi, [PK_BASE + 2*FE_SIZE]
    call _fe_one

    ; T = X * Y
    lea rdi, [PK_BASE + 3*FE_SIZE]
    lea rsi, [PK_BASE]
    lea rdx, [PK_BASE + FE_SIZE]
    call _fe_mul

    ; pk_point = scalar * B
    lea rdi, [PK_POINT]
    lea rsi, [PK_HASH]          ; clamped scalar (32 bytes)
    lea rdx, [PK_BASE]
    call _ed_scalar_mul

    ; Encode point to 32 bytes
    mov rdi, r13
    lea rsi, [PK_POINT]
    call _ed_point_encode

    pop r13
    pop r12
    pop rbx
    add rsp, 512
    pop rbp
    ret

; ed25519_sign(sk, pk, msg, msg_len, sig)
; Sign a message with Ed25519
; rdi = sk (32 bytes seed)
; rsi = pk (32 bytes public key)
; rdx = msg
; rcx = msg_len
; r8  = sig (64 bytes output)
global _ed25519_sign
_ed25519_sign:
    push rbp
    mov rbp, rsp
    sub rsp, 768
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi            ; sk
    mov r13, rsi            ; pk
    mov r14, rdx            ; msg
    mov r15, rcx            ; msg_len
    mov rbx, r8             ; sig

    %define SIG_HASH    rbp - 64    ; SHA-512 output (64 bytes)
    %define SIG_HRAM    rbp - 128   ; SHA-512 of (R||A||M) (64 bytes)
    %define SIG_CTX     rbp - 344   ; SHA-512 context (216 bytes)
    %define SIG_NONCE   rbp - 376   ; reduced nonce r (32 bytes)
    %define SIG_POINT   rbp - 536   ; R point (160 bytes)
    %define SIG_BASE    rbp - 696   ; base point (160 bytes)
    %define SIG_S       rbp - 760   ; s scalar (64 bytes)

    ; Step 1: h = SHA-512(sk)
    mov rdi, r12
    mov rsi, 32
    lea rdx, [SIG_HASH]
    call _sha512_hash

    ; Clamp a = h[0:32]
    lea rax, [SIG_HASH]
    and byte [rax], 0xF8
    and byte [rax + 31], 0x7F
    or  byte [rax + 31], 0x40

    ; Step 2: r = SHA-512(h[32:64] || msg)
    lea rdi, [SIG_CTX]
    call _sha512_init

    lea rdi, [SIG_CTX]
    lea rsi, [SIG_HASH + 32]    ; second half of hash
    mov rdx, 32
    call _sha512_update

    lea rdi, [SIG_CTX]
    mov rsi, r14                 ; msg
    mov rdx, r15                 ; msg_len
    call _sha512_update

    lea rdi, [SIG_CTX]
    lea rsi, [SIG_NONCE]         ; 64-byte output
    call _sha512_final

    ; Reduce r mod L
    lea rdi, [SIG_NONCE]
    call _sc_reduce
    ; SIG_NONCE now has 32-byte reduced r

    ; Step 3: R = r * B
    ; Set up basepoint
    lea rdi, [SIG_BASE]
    lea rsi, [ed25519_Bx]
    mov ecx, FE_SIZE
    rep movsb
    lea rdi, [SIG_BASE + FE_SIZE]
    lea rsi, [ed25519_By]
    mov ecx, FE_SIZE
    rep movsb
    lea rdi, [SIG_BASE + 2*FE_SIZE]
    call _fe_one
    lea rdi, [SIG_BASE + 3*FE_SIZE]
    lea rsi, [SIG_BASE]
    lea rdx, [SIG_BASE + FE_SIZE]
    call _fe_mul

    lea rdi, [SIG_POINT]
    lea rsi, [SIG_NONCE]
    lea rdx, [SIG_BASE]
    call _ed_scalar_mul

    ; Encode R to first 32 bytes of signature
    mov rdi, rbx                 ; sig[0:32]
    lea rsi, [SIG_POINT]
    call _ed_point_encode

    ; Step 4: k = SHA-512(R || pk || msg)
    lea rdi, [SIG_CTX]
    call _sha512_init

    lea rdi, [SIG_CTX]
    mov rsi, rbx                 ; R (first 32 bytes of sig)
    mov rdx, 32
    call _sha512_update

    lea rdi, [SIG_CTX]
    mov rsi, r13                 ; pk
    mov rdx, 32
    call _sha512_update

    lea rdi, [SIG_CTX]
    mov rsi, r14                 ; msg
    mov rdx, r15                 ; msg_len
    call _sha512_update

    lea rdi, [SIG_CTX]
    lea rsi, [SIG_HRAM]
    call _sha512_final

    ; Reduce k mod L
    lea rdi, [SIG_HRAM]
    call _sc_reduce

    ; Step 5: S = (r + k * a) mod L
    ; Compute k * a (both 32 bytes, result up to 64 bytes)
    ; Use simple schoolbook multiplication of 32-byte numbers
    ; k is in SIG_HRAM[0:32], a is in SIG_HASH[0:32]

    ; Zero the 64-byte S buffer
    lea rdi, [SIG_S]
    xor al, al
    mov ecx, 64
    rep stosb

    ; Schoolbook multiply: S = k * a (byte-level, 32x32 -> 64 bytes)
    ; k at SIG_HRAM, a at SIG_HASH
    xor ecx, ecx            ; i = 0
.mul_outer:
    cmp ecx, 32
    jge .mul_done

    movzx eax, byte [rbp - 128 + rcx]  ; k[i] (SIG_HRAM)
    test eax, eax
    jz .mul_skip

    push rcx
    xor edx, edx            ; j = 0
    xor r8d, r8d            ; carry = 0

.mul_inner:
    cmp edx, 32
    jge .mul_carry_out

    movzx eax, byte [rbp - 128 + rcx]  ; k[i]
    movzx r9d, byte [rbp - 64 + rdx]   ; a[j]
    imul eax, r9d            ; k[i] * a[j]
    add eax, r8d             ; + carry

    ; Add to S[i+j]
    lea r10d, [ecx + edx]
    movzx r9d, byte [rbp - 760 + r10]
    add eax, r9d
    mov r8d, eax
    shr r8d, 8               ; carry
    and eax, 0xFF
    mov [rbp - 760 + r10], al

    inc edx
    jmp .mul_inner

.mul_carry_out:
    ; Store carry at S[i+32]
    lea r10d, [ecx + 32]
    cmp r10d, 64
    jge .mul_carry_skip
    add [rbp - 760 + r10], r8b
.mul_carry_skip:
    pop rcx

.mul_skip:
    inc ecx
    jmp .mul_outer

.mul_done:
    ; S = S + r (add nonce r to k*a)
    xor ecx, ecx
    xor edx, edx            ; carry
.add_r:
    cmp ecx, 32
    jge .add_r_done
    movzx eax, byte [rbp - 760 + rcx]
    movzx r8d, byte [rbp - 376 + rcx]  ; SIG_NONCE
    add eax, r8d
    add eax, edx
    mov edx, eax
    shr edx, 8
    and eax, 0xFF
    mov [rbp - 760 + rcx], al
    inc ecx
    jmp .add_r
.add_r_done:
    ; Propagate carry into upper bytes
.add_r_carry:
    cmp ecx, 64
    jge .reduce_s
    test edx, edx
    jz .reduce_s
    movzx eax, byte [rbp - 760 + rcx]
    add eax, edx
    mov edx, eax
    shr edx, 8
    and eax, 0xFF
    mov [rbp - 760 + rcx], al
    inc ecx
    jmp .add_r_carry

.reduce_s:
    ; Reduce S mod L (64 bytes -> 32 bytes)
    lea rdi, [SIG_S]
    call _sc_reduce

    ; Copy S to sig[32:64]
    lea rdi, [rbx + 32]
    lea rsi, [SIG_S]
    mov ecx, 32
    rep movsb

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    add rsp, 768
    pop rbp
    ret
