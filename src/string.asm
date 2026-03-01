; =============================================================================
; string.asm — String/memory utilities
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .text

; memcpy(dst, src, len) -> dst
; rdi=dst, rsi=src, rdx=len
global _memcpy
_memcpy:
    mov rax, rdi        ; return dst
    mov rcx, rdx
    rep movsb
    ret

; memmove(dst, src, len) -> dst
; Handles overlapping regions
global _memmove
_memmove:
    mov rax, rdi
    cmp rdi, rsi
    je .done
    ja .backward
    ; Forward copy (dst < src)
    mov rcx, rdx
    rep movsb
    ret
.backward:
    ; Backward copy (dst > src)
    lea rdi, [rdi + rdx - 1]
    lea rsi, [rsi + rdx - 1]
    mov rcx, rdx
    std
    rep movsb
    cld
.done:
    ret

; memset(dst, byte, len) -> dst
; rdi=dst, esi=byte, rdx=len
global _memset
_memset:
    push rdi            ; save dst for return
    mov al, sil
    mov rcx, rdx
    rep stosb
    pop rax             ; return dst
    ret

; memcmp(a, b, len) -> 0 if equal, nonzero if different
; rdi=a, rsi=b, rdx=len
global _memcmp
_memcmp:
    mov rcx, rdx
    repe cmpsb
    je .equal
    movzx eax, byte [rdi-1]
    movzx ecx, byte [rsi-1]
    sub eax, ecx
    ret
.equal:
    xor eax, eax
    ret

; strlen(str) -> length (not including null)
; rdi=str
global _strlen
_strlen:
    mov rax, rdi
    xor ecx, ecx
    dec ecx             ; rcx = 0xFFFFFFFF (scan up to 4GB)
    xor al, al
    mov rdx, rdi        ; save start
    repne scasb
    sub rdi, rdx
    lea rax, [rdi - 1]  ; length = pos - start - 1
    ret

; strncmp(a, b, maxlen) -> 0 if equal
; rdi=a, rsi=b, rdx=maxlen
global _strncmp
_strncmp:
    test rdx, rdx
    jz .equal
.loop:
    movzx eax, byte [rdi]
    movzx ecx, byte [rsi]
    cmp al, cl
    jne .diff
    test al, al
    jz .equal
    inc rdi
    inc rsi
    dec rdx
    jnz .loop
.equal:
    xor eax, eax
    ret
.diff:
    sub eax, ecx
    ret

; memfind(haystack, haystack_len, needle, needle_len) -> ptr or NULL
; rdi=haystack, rsi=haystack_len, rdx=needle, rcx=needle_len
global _memfind
_memfind:
    FUNC_ENTER
    push rbx
    push r12
    push r13
    push r14

    mov r12, rdi        ; haystack
    mov r13, rsi        ; haystack_len
    mov r14, rdx        ; needle
    mov rbx, rcx        ; needle_len

    ; Edge cases
    test rbx, rbx
    jz .found_at_start
    cmp rbx, r13
    ja .not_found

    ; Simple scan
    mov rcx, r13
    sub rcx, rbx
    inc rcx                 ; number of positions to check
.scan:
    test rcx, rcx
    jz .not_found

    ; Compare needle at current position
    push rcx
    mov rdi, r12
    mov rsi, r14
    mov rdx, rbx
    call _memcmp
    pop rcx
    test eax, eax
    jz .found

    inc r12
    dec rcx
    jmp .scan

.found:
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.found_at_start:
    mov rax, r12
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

.not_found:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    FUNC_LEAVE

; write_be32(buf, value)
; Write a 32-bit value in big-endian (network byte order)
; rdi=buf, esi=value
global _write_be32
_write_be32:
    bswap esi
    mov [rdi], esi
    ret

; read_be32(buf) -> uint32 value
; rdi=buf
global _read_be32
_read_be32:
    mov eax, [rdi]
    bswap eax
    ret

; write_be64(buf, value)
; rdi=buf, rsi=value
global _write_be64
_write_be64:
    bswap rsi
    mov [rdi], rsi
    ret

; read_be64(buf) -> uint64
; rdi=buf
global _read_be64
_read_be64:
    mov rax, [rdi]
    bswap rax
    ret

; ssh_write_string(buf, data, len) -> bytes written (4 + len)
; Writes [uint32 len][data] in SSH format
; rdi=buf, rsi=data, rdx=len
global _ssh_write_string
_ssh_write_string:
    push rbx
    push r12
    mov rbx, rdi        ; buf
    mov r12, rdx        ; len

    ; Write big-endian length
    mov eax, edx
    bswap eax
    mov [rbx], eax

    ; Copy data
    lea rdi, [rbx + 4]
    ; rsi already = data
    mov rcx, r12
    rep movsb

    ; Return 4 + len
    lea rax, [r12 + 4]
    pop r12
    pop rbx
    ret

; ssh_read_string(buf, out_data, out_len) -> bytes consumed or -1
; Reads SSH string: [uint32 len][data]
; rdi=buf, rsi=out_data_ptr (pointer to pointer), rdx=out_len_ptr
global _ssh_read_string
_ssh_read_string:
    ; Read big-endian length
    mov eax, [rdi]
    bswap eax

    ; Sanity check
    cmp eax, SSH_MAX_PACKET_SIZE
    ja .bad_string

    ; Set out_len
    mov [rdx], eax

    ; Set out_data pointer (points into buf)
    lea rcx, [rdi + 4]
    mov [rsi], rcx

    ; Return bytes consumed
    lea eax, [eax + 4]
    ret

.bad_string:
    mov rax, -1
    ret

; itoa_dec(buf, value) -> length
; Convert unsigned 64-bit integer to decimal string
; rdi=buf, rsi=value
global _itoa_dec
_itoa_dec:
    push rbx
    push r12
    mov r12, rdi        ; save buf start
    mov rax, rsi

    ; Handle 0
    test rax, rax
    jnz .nonzero
    mov byte [rdi], '0'
    mov rax, 1
    pop r12
    pop rbx
    ret

.nonzero:
    ; Generate digits in reverse on stack
    xor ecx, ecx       ; digit count
    mov rbx, 10
.div_loop:
    xor edx, edx
    div rbx
    add dl, '0'
    push rdx
    inc ecx
    test rax, rax
    jnz .div_loop

    ; Pop digits into buffer (now in correct order)
    mov rax, rcx        ; save count for return
.store_loop:
    pop rdx
    mov [rdi], dl
    inc rdi
    dec ecx
    jnz .store_loop

    pop r12
    pop rbx
    ret

; hex_byte(buf, byte) — write 2 hex chars
; rdi=buf, sil=byte
global _hex_byte
_hex_byte:
    movzx eax, sil
    shr al, 4
    cmp al, 10
    jb .hi_digit
    add al, 'a' - 10
    jmp .hi_done
.hi_digit:
    add al, '0'
.hi_done:
    mov [rdi], al

    movzx eax, sil
    and al, 0x0F
    cmp al, 10
    jb .lo_digit
    add al, 'a' - 10
    jmp .lo_done
.lo_digit:
    add al, '0'
.lo_done:
    mov [rdi+1], al
    ret
