; =============================================================================
; constants.asm — macOS x86_64 syscall numbers + SSH protocol constants
; =============================================================================

; --- macOS syscall numbers (add 0x2000000 for BSD class) ---
%define SYS_CLASS       0x2000000
%define SYS_exit        (SYS_CLASS | 1)
%define SYS_fork        (SYS_CLASS | 2)
%define SYS_read        (SYS_CLASS | 3)
%define SYS_write       (SYS_CLASS | 4)
%define SYS_open        (SYS_CLASS | 5)
%define SYS_close       (SYS_CLASS | 6)
%define SYS_wait4       (SYS_CLASS | 7)
%define SYS_unlink      (SYS_CLASS | 10)
%define SYS_chdir       (SYS_CLASS | 12)
%define SYS_getpid      (SYS_CLASS | 20)
%define SYS_getuid      (SYS_CLASS | 24)
%define SYS_kill        (SYS_CLASS | 37)
%define SYS_dup2        (SYS_CLASS | 90)
%define SYS_socket      (SYS_CLASS | 97)
%define SYS_connect     (SYS_CLASS | 98)
%define SYS_accept      (SYS_CLASS | 30)
%define SYS_bind        (SYS_CLASS | 104)
%define SYS_listen      (SYS_CLASS | 106)
%define SYS_setsockopt  (SYS_CLASS | 105)
%define SYS_getsockopt  (SYS_CLASS | 118)
%define SYS_ioctl       (SYS_CLASS | 54)
%define SYS_select      (SYS_CLASS | 93)
%define SYS_poll        (SYS_CLASS | 230)
%define SYS_mmap        (SYS_CLASS | 197)
%define SYS_munmap      (SYS_CLASS | 73)
%define SYS_mprotect    (SYS_CLASS | 74)
%define SYS_nanosleep   (SYS_CLASS | 240)
%define SYS_setsid      (SYS_CLASS | 147)
%define SYS_execve      (SYS_CLASS | 59)
%define SYS_sigaction   (SYS_CLASS | 46)
%define SYS_sigprocmask (SYS_CLASS | 48)
%define SYS_getentropy  (SYS_CLASS | 500)
%define SYS_posix_openpt (SYS_CLASS | 349)
%define SYS_grantpt     (SYS_CLASS | 350)
%define SYS_revoke      (SYS_CLASS | 56)
%define SYS_open_dprotected_np (SYS_CLASS | 88)
%define SYS_fcntl       (SYS_CLASS | 92)
%define SYS_fstat       (SYS_CLASS | 339)
%define SYS_stat        (SYS_CLASS | 340)
%define SYS_lseek       (SYS_CLASS | 199)
%define SYS_ptsname     0               ; not a syscall, done via ioctl
%define SYS_shutdown    (SYS_CLASS | 134)
%define SYS_getpeername (SYS_CLASS | 31)
%define SYS_gettimeofday (SYS_CLASS | 116)

; --- open() flags ---
%define O_RDONLY    0x0000
%define O_WRONLY    0x0001
%define O_RDWR      0x0002
%define O_CREAT     0x0200
%define O_TRUNC     0x0400
%define O_NOCTTY    0x20000

; --- fcntl ---
%define F_GETFL     3
%define F_SETFL     4
%define O_NONBLOCK  0x0004

; --- mmap flags ---
%define PROT_NONE   0x00
%define PROT_READ   0x01
%define PROT_WRITE  0x02
%define PROT_EXEC   0x04
%define MAP_ANON    0x1000
%define MAP_PRIVATE 0x0002

; --- socket constants ---
%define AF_INET     2
%define SOCK_STREAM 1
%define SOL_SOCKET  0xFFFF
%define SO_REUSEADDR 0x0004
%define SO_REUSEPORT 0x0200
%define IPPROTO_TCP 6
%define SHUT_RDWR   2

; --- signal constants ---
%define SIGPIPE     13
%define SIGCHLD     20
%define SIGTERM     15
%define SIGINT      2
%define SIG_IGN     1
%define SA_RESTART  0x0002
%define SA_NOCLDWAIT 0x0020

; --- poll constants ---
%define POLLIN      0x0001
%define POLLOUT     0x0004
%define POLLERR     0x0008
%define POLLHUP     0x0010
%define POLLNVAL    0x0020

; --- ioctl codes for PTY (macOS) ---
%define TIOCPTYGRANT  0x20007454    ; _IO('t', 84)
%define TIOCPTYUNLK   0x20007452    ; _IO('t', 82)
%define TIOCPTSNAME   0x40087448    ; not standard, use ptsname ioctl
%define TIOCGPTN      0x40047546    ; not on macOS, use TIOCPTYGRANT/TIOCPTYUNLK
%define TIOCSWINSZ    0x80087467    ; _IOW('t', 103, struct winsize)
%define TIOCGWINSZ    0x40087468    ; _IOR('t', 104, struct winsize)
%define TIOCSCTTY     0x20007461    ; _IO('t', 97)

; --- wait flags ---
%define WNOHANG     1

; --- SSH protocol message types (RFC 4253, 4254) ---
%define SSH_MSG_DISCONNECT              1
%define SSH_MSG_IGNORE                  2
%define SSH_MSG_UNIMPLEMENTED           3
%define SSH_MSG_DEBUG                   4
%define SSH_MSG_SERVICE_REQUEST         5
%define SSH_MSG_SERVICE_ACCEPT          6
%define SSH_MSG_KEXINIT                 20
%define SSH_MSG_NEWKEYS                 21
%define SSH_MSG_KEX_ECDH_INIT          30
%define SSH_MSG_KEX_ECDH_REPLY         31
%define SSH_MSG_USERAUTH_REQUEST        50
%define SSH_MSG_USERAUTH_FAILURE        51
%define SSH_MSG_USERAUTH_SUCCESS        52
%define SSH_MSG_USERAUTH_BANNER         53
%define SSH_MSG_USERAUTH_PK_OK          60
%define SSH_MSG_GLOBAL_REQUEST          80
%define SSH_MSG_REQUEST_SUCCESS         81
%define SSH_MSG_REQUEST_FAILURE         82
%define SSH_MSG_CHANNEL_OPEN            90
%define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
%define SSH_MSG_CHANNEL_OPEN_FAILURE    92
%define SSH_MSG_CHANNEL_WINDOW_ADJUST   93
%define SSH_MSG_CHANNEL_DATA            94
%define SSH_MSG_CHANNEL_EXTENDED_DATA   95
%define SSH_MSG_CHANNEL_EOF             96
%define SSH_MSG_CHANNEL_CLOSE           97
%define SSH_MSG_CHANNEL_REQUEST         98
%define SSH_MSG_CHANNEL_SUCCESS         99
%define SSH_MSG_CHANNEL_FAILURE         100

; --- SSH disconnect reason codes ---
%define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      1
%define SSH_DISCONNECT_PROTOCOL_ERROR                   2
%define SSH_DISCONNECT_KEY_EXCHANGE_FAILED               3
%define SSH_DISCONNECT_RESERVED                         4
%define SSH_DISCONNECT_MAC_ERROR                        5
%define SSH_DISCONNECT_COMPRESSION_ERROR                6
%define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE             7
%define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED    8
%define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE           9
%define SSH_DISCONNECT_CONNECTION_LOST                   10
%define SSH_DISCONNECT_BY_APPLICATION                    11
%define SSH_DISCONNECT_TOO_MANY_CONNECTIONS              12
%define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER            13
%define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE    14
%define SSH_DISCONNECT_ILLEGAL_USER_NAME                 15

; --- SSH limits ---
%define SSH_MAX_PACKET_SIZE     35000
%define SSH_MAX_CHANNELS        16
%define SSH_MAX_SESSIONS        64
%define SSH_MAX_AUTH_ATTEMPTS    6
%define SSH_CHANNEL_WINDOW_SIZE 2097152  ; 2 MB
%define SSH_CHANNEL_MAX_PACKET  32768
%define SSH_REKEY_BYTES         1073741824  ; 1 GB
%define SSH_IDLE_TIMEOUT_SEC    900         ; 15 min

; --- Session structure offsets ---
; Total size: 8192 bytes (2 pages)
%define SESS_SIZE               8192
%define SESS_FD                 0       ; int32
%define SESS_STATE              4       ; int32 (0=init, 1=kex, 2=auth, 3=connected, 4=closing)
%define SESS_SEQ_SEND           8       ; uint32
%define SESS_SEQ_RECV           12      ; uint32
%define SESS_SESSION_ID         16      ; 32 bytes (SHA-256 hash)
%define SESS_SEND_BUF           48      ; 8 bytes (pointer to 64KB buffer)
%define SESS_RECV_BUF           56      ; 8 bytes (pointer to 64KB buffer)
%define SESS_RECV_BUF_LEN       64      ; uint32 (bytes in recv buf)
%define SESS_RECV_BUF_POS       68      ; uint32 (read position)
%define SESS_SEND_CIPHER        72      ; int32 (0=none, 1=aes128-ctr, 2=aes256-ctr, 3=chacha20-poly1305)
%define SESS_RECV_CIPHER        76      ; int32
%define SESS_SEND_KEY           80      ; 64 bytes (encryption key)
%define SESS_RECV_KEY           144     ; 64 bytes (decryption key)
%define SESS_SEND_IV            208     ; 16 bytes
%define SESS_RECV_IV            224     ; 16 bytes
%define SESS_SEND_MAC_KEY       240     ; 32 bytes
%define SESS_RECV_MAC_KEY       272     ; 32 bytes
%define SESS_SEND_AES_SCHED     304     ; 240 bytes (AES key schedule)
%define SESS_RECV_AES_SCHED     544     ; 240 bytes
%define SESS_CLIENT_VERSION     784     ; 256 bytes (client version string)
%define SESS_CLIENT_VERSION_LEN 1040    ; uint32
%define SESS_SERVER_VERSION     1044    ; 256 bytes (server version string)
%define SESS_SERVER_VERSION_LEN 1300    ; uint32
%define SESS_CLIENT_KEXINIT     1304    ; 8 bytes (pointer to raw KEXINIT payload)
%define SESS_CLIENT_KEXINIT_LEN 1312    ; uint32
%define SESS_SERVER_KEXINIT     1316    ; 8 bytes (pointer to raw KEXINIT payload)
%define SESS_SERVER_KEXINIT_LEN 1324    ; uint32
%define SESS_KEX_SHARED_SECRET  1328    ; 32 bytes (X25519 shared secret)
%define SESS_KEX_EXCHANGE_HASH  1360    ; 32 bytes (H)
%define SESS_AUTH_USER          1392    ; 64 bytes (username)
%define SESS_AUTH_USER_LEN      1456    ; uint32
%define SESS_AUTH_ATTEMPTS      1460    ; uint32
%define SESS_CHANNELS           1464    ; 16 * 256 = 4096 bytes (channel array)
%define SESS_NUM_CHANNELS       5560    ; uint32
%define SESS_HOST_KEY_PRIV      5564    ; 64 bytes (Ed25519 private key)
%define SESS_HOST_KEY_PUB       5628    ; 32 bytes (Ed25519 public key)
%define SESS_BYTES_SENT         5660    ; uint64 (for rekey tracking)
%define SESS_BYTES_RECV         5668    ; uint64
%define SESS_LAST_ACTIVITY      5676    ; uint64 (timestamp)
%define SESS_SEND_CHACHA_KEY    5684    ; 64 bytes (K1=32 header + K2=32 main)
%define SESS_RECV_CHACHA_KEY    5748    ; 64 bytes

; --- Channel structure offsets (256 bytes each) ---
%define CHAN_SIZE                256
%define CHAN_ACTIVE              0       ; uint32 (0=free, 1=active)
%define CHAN_LOCAL_ID            4       ; uint32
%define CHAN_REMOTE_ID           8       ; uint32
%define CHAN_LOCAL_WINDOW        12      ; uint32
%define CHAN_REMOTE_WINDOW       16      ; uint32
%define CHAN_LOCAL_MAX_PACKET    20      ; uint32
%define CHAN_REMOTE_MAX_PACKET   24      ; uint32
%define CHAN_PTY_MASTER          28      ; int32 (fd)
%define CHAN_PTY_SLAVE           32      ; int32 (fd)
%define CHAN_CHILD_PID           36      ; int32
%define CHAN_STATE               40      ; int32 (0=init, 1=open, 2=eof_sent, 3=closing, 4=closed)
%define CHAN_TERM_ROWS           44      ; uint32
%define CHAN_TERM_COLS           48      ; uint32
%define CHAN_TERM_XPIXEL         52      ; uint32
%define CHAN_TERM_YPIXEL         56      ; uint32
%define CHAN_PTY_NAME            60      ; 64 bytes (PTY slave path)
%define CHAN_WANT_REPLY          124     ; uint8 (for channel requests)

; --- Server config ---
%define DEFAULT_PORT            2222
%define LISTEN_BACKLOG          16
