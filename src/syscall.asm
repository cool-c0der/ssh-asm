; =============================================================================
; syscall.asm — macOS x86_64 syscall wrappers
; All wrappers return: rax = result (>=0 success), rax = -errno on error
; =============================================================================

%include "constants.asm"
%include "macros.asm"

section .text

; --- Convert macOS syscall result to Linux-style ---
; macOS: CF=1 on error, rax=errno (positive)
; We negate to -errno on error for consistent checking
; Input: rax = raw result, CF = error flag
; Output: rax = result or -errno
%macro SYSCALL_RETURN 0
    jnc %%ok
    neg rax         ; rax = -errno
%%ok:
%endmacro

; ----- Process -----

; sys_exit(int status)
global _sys_exit
_sys_exit:
    SYSCALL SYS_exit
    ; never returns

; sys_fork() -> pid_t (0=child, >0=parent gets child pid, <0=error)
; macOS fork() returns: rax=child_pid in BOTH, rdx=0 parent, rdx=1 child
global _sys_fork
_sys_fork:
    SYSCALL SYS_fork
    jc .fork_err
    ; Check rdx to determine parent vs child
    test edx, edx
    jnz .fork_child
    ; Parent: rax = child PID (already correct)
    ret
.fork_child:
    xor eax, eax           ; Return 0 for child
    ret
.fork_err:
    neg rax
    ret

; sys_getpid() -> pid_t
global _sys_getpid
_sys_getpid:
    SYSCALL SYS_getpid
    ret

; sys_getuid() -> uid_t
global _sys_getuid
_sys_getuid:
    SYSCALL SYS_getuid
    ret

; sys_wait4(pid, *status, options, *rusage) -> pid_t
global _sys_wait4
_sys_wait4:
    mov r10, rcx    ; macOS uses r10 for 4th arg
    SYSCALL SYS_wait4
    SYSCALL_RETURN
    ret

; sys_execve(path, argv, envp)
global _sys_execve
_sys_execve:
    SYSCALL SYS_execve
    SYSCALL_RETURN
    ret

; sys_setsid() -> pid_t
global _sys_setsid
_sys_setsid:
    SYSCALL SYS_setsid
    SYSCALL_RETURN
    ret

; sys_kill(pid, sig) -> int
global _sys_kill
_sys_kill:
    SYSCALL SYS_kill
    SYSCALL_RETURN
    ret

; sys_nanosleep(req, rem) -> int
global _sys_nanosleep
_sys_nanosleep:
    SYSCALL SYS_nanosleep
    SYSCALL_RETURN
    ret

; sys_gettimeofday(tv, tz) -> int
global _sys_gettimeofday
_sys_gettimeofday:
    SYSCALL SYS_gettimeofday
    SYSCALL_RETURN
    ret

; ----- File I/O -----

; sys_open(path, flags, mode) -> fd
global _sys_open
_sys_open:
    SYSCALL SYS_open
    SYSCALL_RETURN
    ret

; sys_close(fd) -> int
global _sys_close
_sys_close:
    SYSCALL SYS_close
    SYSCALL_RETURN
    ret

; sys_read(fd, buf, count) -> ssize_t
global _sys_read
_sys_read:
    SYSCALL SYS_read
    SYSCALL_RETURN
    ret

; sys_write(fd, buf, count) -> ssize_t
global _sys_write
_sys_write:
    SYSCALL SYS_write
    SYSCALL_RETURN
    ret

; sys_dup2(oldfd, newfd) -> fd
global _sys_dup2
_sys_dup2:
    SYSCALL SYS_dup2
    SYSCALL_RETURN
    ret

; sys_ioctl(fd, request, arg) -> int
global _sys_ioctl
_sys_ioctl:
    SYSCALL SYS_ioctl
    SYSCALL_RETURN
    ret

; sys_fcntl(fd, cmd, arg) -> int
global _sys_fcntl
_sys_fcntl:
    SYSCALL SYS_fcntl
    SYSCALL_RETURN
    ret

; sys_lseek(fd, offset, whence) -> off_t
global _sys_lseek
_sys_lseek:
    SYSCALL SYS_lseek
    SYSCALL_RETURN
    ret

; sys_fstat(fd, stat_buf) -> int
global _sys_fstat
_sys_fstat:
    SYSCALL SYS_fstat
    SYSCALL_RETURN
    ret

; sys_stat(path, stat_buf) -> int
global _sys_stat
_sys_stat:
    SYSCALL SYS_stat
    SYSCALL_RETURN
    ret

; sys_unlink(path) -> int
global _sys_unlink
_sys_unlink:
    SYSCALL SYS_unlink
    SYSCALL_RETURN
    ret

; sys_chdir(path) -> int
global _sys_chdir
_sys_chdir:
    SYSCALL SYS_chdir
    SYSCALL_RETURN
    ret

; ----- Network -----

; sys_socket(domain, type, protocol) -> fd
global _sys_socket
_sys_socket:
    SYSCALL SYS_socket
    SYSCALL_RETURN
    ret

; sys_bind(fd, addr, addrlen) -> int
global _sys_bind
_sys_bind:
    SYSCALL SYS_bind
    SYSCALL_RETURN
    ret

; sys_listen(fd, backlog) -> int
global _sys_listen
_sys_listen:
    SYSCALL SYS_listen
    SYSCALL_RETURN
    ret

; sys_accept(fd, addr, addrlen) -> fd
global _sys_accept
_sys_accept:
    SYSCALL SYS_accept
    SYSCALL_RETURN
    ret

; sys_connect(fd, addr, addrlen) -> int
global _sys_connect
_sys_connect:
    SYSCALL SYS_connect
    SYSCALL_RETURN
    ret

; sys_setsockopt(fd, level, optname, optval, optlen) -> int
global _sys_setsockopt
_sys_setsockopt:
    mov r10, rcx
    SYSCALL SYS_setsockopt
    SYSCALL_RETURN
    ret

; sys_shutdown(fd, how) -> int
global _sys_shutdown
_sys_shutdown:
    SYSCALL SYS_shutdown
    SYSCALL_RETURN
    ret

; sys_getpeername(fd, addr, addrlen) -> int
global _sys_getpeername
_sys_getpeername:
    SYSCALL SYS_getpeername
    SYSCALL_RETURN
    ret

; sys_poll(fds, nfds, timeout) -> int
global _sys_poll
_sys_poll:
    SYSCALL SYS_poll
    SYSCALL_RETURN
    ret

; ----- Memory -----

; sys_mmap(addr, len, prot, flags, fd, offset) -> ptr
global _sys_mmap
_sys_mmap:
    mov r10, rcx    ; flags (4th arg)
    SYSCALL SYS_mmap
    SYSCALL_RETURN
    ret

; sys_munmap(addr, len) -> int
global _sys_munmap
_sys_munmap:
    SYSCALL SYS_munmap
    SYSCALL_RETURN
    ret

; sys_mprotect(addr, len, prot) -> int
global _sys_mprotect
_sys_mprotect:
    SYSCALL SYS_mprotect
    SYSCALL_RETURN
    ret

; ----- Signal -----

; sys_sigaction(signum, act, oldact) -> int
; macOS sigaction struct: handler(8), mask(4), flags(4) = 16 bytes
global _sys_sigaction
_sys_sigaction:
    SYSCALL SYS_sigaction
    SYSCALL_RETURN
    ret

; sys_sigprocmask(how, set, oldset) -> int
global _sys_sigprocmask
_sys_sigprocmask:
    SYSCALL SYS_sigprocmask
    SYSCALL_RETURN
    ret

; ----- Randomness -----

; sys_getentropy(buf, buflen) -> int
; buflen must be <= 256
global _sys_getentropy
_sys_getentropy:
    SYSCALL SYS_getentropy
    SYSCALL_RETURN
    ret

; ----- PTY -----

; sys_posix_openpt(flags) -> fd
global _sys_posix_openpt
_sys_posix_openpt:
    SYSCALL SYS_posix_openpt
    SYSCALL_RETURN
    ret

; sys_revoke(path) -> int
global _sys_revoke
_sys_revoke:
    SYSCALL SYS_revoke
    SYSCALL_RETURN
    ret
