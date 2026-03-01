; =============================================================================
; memory.asm — mmap-based bump allocator
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .data
    ; Bump allocator state
    heap_base:  dq 0    ; Start of current heap region
    heap_ptr:   dq 0    ; Current allocation pointer
    heap_end:   dq 0    ; End of current heap region
    heap_total: dq 0    ; Total bytes allocated via mmap

section .text

; Initial heap size: 1 MB
%define HEAP_INIT_SIZE  (1024 * 1024)
; Grow by 1 MB at a time
%define HEAP_GROW_SIZE  (1024 * 1024)

; mem_init() — initialize the heap
; Returns: 0 on success, -1 on error
global _mem_init
_mem_init:
    FUNC_ENTER

    ; mmap(NULL, HEAP_INIT_SIZE, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0)
    xor rdi, rdi                        ; addr = NULL
    mov rsi, HEAP_INIT_SIZE             ; length
    mov rdx, PROT_READ | PROT_WRITE     ; prot
    mov r10, MAP_ANON | MAP_PRIVATE     ; flags
    mov r8, -1                          ; fd = -1
    xor r9, r9                          ; offset = 0
    SYSCALL SYS_mmap
    test rax, rax
    js .fail

    lea rcx, [rel heap_base]
    mov [rcx], rax
    lea rcx, [rel heap_ptr]
    mov [rcx], rax
    lea rcx, [rel heap_end]
    add rax, HEAP_INIT_SIZE
    mov [rcx], rax
    lea rcx, [rel heap_total]
    mov qword [rcx], HEAP_INIT_SIZE

    xor eax, eax
    FUNC_LEAVE

.fail:
    mov rax, -1
    FUNC_LEAVE

; mem_alloc(size) -> ptr or NULL
; rdi = size (rounded up to 16-byte alignment)
global _mem_alloc
_mem_alloc:
    FUNC_ENTER
    push rbx
    push r12

    ; Align size to 16 bytes
    add rdi, 15
    and rdi, ~15
    mov r12, rdi            ; r12 = aligned size

    ; Check if we have space
    lea rbx, [rel heap_ptr]
    mov rax, [rbx]          ; current ptr
    add rax, r12
    lea rcx, [rel heap_end]
    cmp rax, [rcx]
    ja .grow

.alloc:
    ; Bump allocate
    mov rax, [rbx]          ; return current ptr
    add qword [rbx], r12    ; advance pointer

    pop r12
    pop rbx
    FUNC_LEAVE

.grow:
    ; Need more memory — mmap another chunk
    push r12
    xor rdi, rdi
    mov rsi, HEAP_GROW_SIZE
    ; If requested size > grow size, use larger
    cmp r12, rsi
    cmova rsi, r12
    ; Round up to page size (4096)
    add rsi, 4095
    and rsi, ~4095
    push rsi                ; save actual mmap size

    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_ANON | MAP_PRIVATE
    mov r8, -1
    xor r9, r9
    SYSCALL SYS_mmap
    pop rsi                 ; restore mmap size
    pop r12

    test rax, rax
    js .fail_alloc

    ; Update heap state to new region
    lea rbx, [rel heap_base]
    mov [rbx], rax
    lea rbx, [rel heap_ptr]
    mov [rbx], rax
    lea rcx, [rel heap_end]
    lea rdx, [rax + rsi]
    mov [rcx], rdx
    lea rcx, [rel heap_total]
    add [rcx], rsi

    jmp .alloc

.fail_alloc:
    xor eax, eax           ; return NULL
    pop r12
    pop rbx
    FUNC_LEAVE

; mem_alloc_zeroed(size) -> ptr or NULL
; Same as mem_alloc but zeroes the memory
global _mem_alloc_zeroed
_mem_alloc_zeroed:
    FUNC_ENTER
    push rbx

    mov rbx, rdi            ; save size
    call _mem_alloc
    test rax, rax
    jz .done

    ; Zero the memory (mmap should be zeroed, but be safe)
    push rax
    mov rdi, rax
    xor esi, esi
    mov rdx, rbx
    call _memset
    pop rax

.done:
    pop rbx
    FUNC_LEAVE

; mem_alloc_page(n_pages) -> ptr or NULL
; Allocates n_pages * 4096 bytes directly via mmap
; Good for sensitive data that will be explicitly munmap'd
global _mem_alloc_page
_mem_alloc_page:
    FUNC_ENTER

    shl rdi, 12             ; n_pages * 4096
    mov rsi, rdi
    xor rdi, rdi
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_ANON | MAP_PRIVATE
    mov r8, -1
    xor r9, r9
    SYSCALL SYS_mmap
    test rax, rax
    js .fail_page
    FUNC_LEAVE

.fail_page:
    xor eax, eax
    FUNC_LEAVE

; mem_free_page(ptr, n_pages)
; Zeroes and unmaps pages
global _mem_free_page
_mem_free_page:
    FUNC_ENTER
    push rbx
    push r12

    mov rbx, rdi            ; ptr
    mov r12, rsi
    shl r12, 12             ; n_pages * 4096

    ; Zero the memory first (security)
    mov rdi, rbx
    xor esi, esi
    mov rdx, r12
    call _memset

    ; munmap
    mov rdi, rbx
    mov rsi, r12
    SYSCALL SYS_munmap

    pop r12
    pop rbx
    FUNC_LEAVE

; External reference
extern _memset
