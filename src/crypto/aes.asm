; =============================================================================
; aes.asm — AES-128/256 key expansion + single-block encrypt using AES-NI
;
; Uses: aeskeygenassist, aesenc, aesenclast
; Key schedule stored as 16-byte aligned xmm blocks
; AES-128: 11 round keys (176 bytes)
; AES-256: 15 round keys (240 bytes)
; =============================================================================

default rel
%include "constants.asm"
%include "macros.asm"

section .text

; --- AES-128 Key Expansion ---
; aes128_expand_key(key, schedule)
; rdi = 16-byte key, rsi = 176-byte output (11 round keys, 16-byte aligned)
global _aes128_expand_key
_aes128_expand_key:
    movdqu xmm1, [rdi]          ; load key
    movdqa [rsi], xmm1          ; round key 0

    aeskeygenassist xmm2, xmm1, 0x01
    call .expand128
    movdqa [rsi + 16], xmm1

    aeskeygenassist xmm2, xmm1, 0x02
    call .expand128
    movdqa [rsi + 32], xmm1

    aeskeygenassist xmm2, xmm1, 0x04
    call .expand128
    movdqa [rsi + 48], xmm1

    aeskeygenassist xmm2, xmm1, 0x08
    call .expand128
    movdqa [rsi + 64], xmm1

    aeskeygenassist xmm2, xmm1, 0x10
    call .expand128
    movdqa [rsi + 80], xmm1

    aeskeygenassist xmm2, xmm1, 0x20
    call .expand128
    movdqa [rsi + 96], xmm1

    aeskeygenassist xmm2, xmm1, 0x40
    call .expand128
    movdqa [rsi + 112], xmm1

    aeskeygenassist xmm2, xmm1, 0x80
    call .expand128
    movdqa [rsi + 128], xmm1

    aeskeygenassist xmm2, xmm1, 0x1b
    call .expand128
    movdqa [rsi + 144], xmm1

    aeskeygenassist xmm2, xmm1, 0x36
    call .expand128
    movdqa [rsi + 160], xmm1

    ret

; Internal: expand one AES-128 round key
; xmm1 = current key, xmm2 = aeskeygenassist result
; Output: xmm1 = next round key
.expand128:
    pshufd xmm2, xmm2, 0xFF    ; broadcast highest dword
    movdqa xmm3, xmm1
    pslldq xmm3, 4              ; shift left 4 bytes
    pxor xmm1, xmm3
    movdqa xmm3, xmm1
    pslldq xmm3, 4
    pxor xmm1, xmm3
    movdqa xmm3, xmm1
    pslldq xmm3, 4
    pxor xmm1, xmm3
    pxor xmm1, xmm2
    ret

; --- AES-256 Key Expansion ---
; aes256_expand_key(key, schedule)
; rdi = 32-byte key, rsi = 240-byte output (15 round keys)
global _aes256_expand_key
_aes256_expand_key:
    movdqu xmm1, [rdi]          ; first half of key
    movdqu xmm3, [rdi + 16]     ; second half
    movdqa [rsi], xmm1          ; round key 0
    movdqa [rsi + 16], xmm3     ; round key 1

    ; Generate round keys 2..14
    ; For AES-256: alternating between two expansion types
    aeskeygenassist xmm2, xmm3, 0x01
    call .expand256_1
    movdqa [rsi + 32], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 48], xmm3

    aeskeygenassist xmm2, xmm3, 0x02
    call .expand256_1
    movdqa [rsi + 64], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 80], xmm3

    aeskeygenassist xmm2, xmm3, 0x04
    call .expand256_1
    movdqa [rsi + 96], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 112], xmm3

    aeskeygenassist xmm2, xmm3, 0x08
    call .expand256_1
    movdqa [rsi + 128], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 144], xmm3

    aeskeygenassist xmm2, xmm3, 0x10
    call .expand256_1
    movdqa [rsi + 160], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 176], xmm3

    aeskeygenassist xmm2, xmm3, 0x20
    call .expand256_1
    movdqa [rsi + 192], xmm1
    aeskeygenassist xmm2, xmm1, 0x00
    call .expand256_2
    movdqa [rsi + 208], xmm3

    aeskeygenassist xmm2, xmm3, 0x40
    call .expand256_1
    movdqa [rsi + 224], xmm1
    ; No more round keys needed (14 rounds = 15 keys, 0..14)

    ret

; AES-256 expansion type 1 (odd rounds): uses pshufd 0xFF
.expand256_1:
    pshufd xmm2, xmm2, 0xFF
    movdqa xmm4, xmm1
    pslldq xmm4, 4
    pxor xmm1, xmm4
    movdqa xmm4, xmm1
    pslldq xmm4, 4
    pxor xmm1, xmm4
    movdqa xmm4, xmm1
    pslldq xmm4, 4
    pxor xmm1, xmm4
    pxor xmm1, xmm2
    ret

; AES-256 expansion type 2 (even rounds): uses pshufd 0xAA
.expand256_2:
    pshufd xmm2, xmm2, 0xAA
    movdqa xmm4, xmm3
    pslldq xmm4, 4
    pxor xmm3, xmm4
    movdqa xmm4, xmm3
    pslldq xmm4, 4
    pxor xmm3, xmm4
    movdqa xmm4, xmm3
    pslldq xmm4, 4
    pxor xmm3, xmm4
    pxor xmm3, xmm2
    ret

; --- AES single block encrypt ---
; aes_encrypt_block(schedule, n_rounds, plaintext, ciphertext)
; rdi = schedule (aligned), esi = rounds (10 or 14), rdx = 16-byte in, rcx = 16-byte out
global _aes_encrypt_block
_aes_encrypt_block:
    movdqu xmm0, [rdx]          ; load plaintext
    pxor xmm0, [rdi]            ; AddRoundKey(0)

    ; Rounds 1..n-1
    add rdi, 16                  ; advance to round key 1
    mov eax, 1
.enc_loop:
    movdqa xmm1, [rdi]
    aesenc xmm0, xmm1
    add rdi, 16
    inc eax
    cmp eax, esi
    jl .enc_loop

    ; Final round
    movdqa xmm1, [rdi]
    aesenclast xmm0, xmm1

    movdqu [rcx], xmm0          ; store ciphertext
    ret
