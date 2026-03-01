# =============================================================================
# Makefile — Pure x86_64 NASM SSH Server for macOS
# =============================================================================

NASM := nasm
NASMFLAGS := -f macho64 -I src/ -w-label-redef-late
LD := ld
LDFLAGS := -arch x86_64 -e _main -static -platform_version macos 14.0.0 14.0.0

# Source directories
SRCDIR := src
OBJDIR := obj
BINDIR := bin
TESTDIR := test

# Source files (order matters for dependencies)
SRCS := \
	$(SRCDIR)/syscall.asm \
	$(SRCDIR)/memory.asm \
	$(SRCDIR)/string.asm \
	$(SRCDIR)/io.asm \
	$(SRCDIR)/log.asm \
	$(SRCDIR)/signal.asm \
	$(SRCDIR)/process.asm \
	$(SRCDIR)/net/tcp.asm \
	$(SRCDIR)/main.asm

# Object files
OBJS := $(patsubst $(SRCDIR)/%.asm,$(OBJDIR)/%.o,$(SRCS))

# Main binary
TARGET := $(BINDIR)/ssh-asm

# Crypto sources
CRYPTO_SRCS := \
	$(SRCDIR)/crypto/sha256.asm \
	$(SRCDIR)/crypto/sha512.asm \
	$(SRCDIR)/crypto/hmac.asm \
	$(SRCDIR)/crypto/aes.asm \
	$(SRCDIR)/crypto/aes_ctr.asm \
	$(SRCDIR)/crypto/chacha20.asm \
	$(SRCDIR)/crypto/poly1305.asm \
	$(SRCDIR)/crypto/chacha20poly1305.asm \
	$(SRCDIR)/crypto/bignum.asm \
	$(SRCDIR)/crypto/field25519.asm \
	$(SRCDIR)/crypto/curve25519.asm \
	$(SRCDIR)/crypto/ed25519.asm \
	$(SRCDIR)/crypto/random.asm \
	$(SRCDIR)/crypto/constant_time.asm

CRYPTO_OBJS := $(patsubst $(SRCDIR)/%.asm,$(OBJDIR)/%.o,$(CRYPTO_SRCS))

# SSH protocol sources
SSH_SRCS := \
	$(SRCDIR)/ssh/packet.asm \
	$(SRCDIR)/ssh/kex.asm \
	$(SRCDIR)/ssh/kdf.asm \
	$(SRCDIR)/ssh/auth.asm \
	$(SRCDIR)/ssh/channel.asm \
	$(SRCDIR)/ssh/pty.asm \
	$(SRCDIR)/ssh/session.asm

SSH_OBJS := $(patsubst $(SRCDIR)/%.asm,$(OBJDIR)/%.o,$(SSH_SRCS))

# All objects for final binary
ALL_OBJS = $(OBJS) $(CRYPTO_OBJS) $(SSH_OBJS)

.PHONY: all clean test run phase1

all: $(TARGET)

$(TARGET): $(ALL_OBJS) | $(BINDIR)
	$(LD) $(LDFLAGS) -o $@ $(ALL_OBJS)
	@echo "Built $@"

# Phase 1: just foundation files
phase1: $(OBJS) | $(BINDIR)
	$(LD) $(LDFLAGS) -o $(BINDIR)/ssh-asm $(OBJS)
	@echo "Built Phase 1: $(BINDIR)/ssh-asm"

# Compile .asm -> .o
$(OBJDIR)/%.o: $(SRCDIR)/%.asm | $(OBJDIR)
	@mkdir -p $(dir $@)
	$(NASM) $(NASMFLAGS) -o $@ $<

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)/net $(OBJDIR)/crypto $(OBJDIR)/ssh

$(BINDIR):
	mkdir -p $(BINDIR)

# Run the server
run: all
	$(BINDIR)/ssh-asm

# Test targets

# Foundation objects needed by most tests
TEST_FOUNDATION := $(OBJDIR)/syscall.o $(OBJDIR)/string.o $(OBJDIR)/memory.o \
                   $(OBJDIR)/io.o $(OBJDIR)/log.o

test_sha256: $(TEST_FOUNDATION) $(OBJDIR)/crypto/sha256.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_sha256.o $(TESTDIR)/test_sha256.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_sha256 \
		$(OBJDIR)/test/test_sha256.o $(OBJDIR)/crypto/sha256.o \
		$(TEST_FOUNDATION)

test_sha512: $(TEST_FOUNDATION) $(OBJDIR)/crypto/sha512.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_sha512.o $(TESTDIR)/test_sha512.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_sha512 \
		$(OBJDIR)/test/test_sha512.o $(OBJDIR)/crypto/sha512.o \
		$(TEST_FOUNDATION)

test_aes: $(TEST_FOUNDATION) $(OBJDIR)/crypto/aes.o $(OBJDIR)/crypto/aes_ctr.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_aes.o $(TESTDIR)/test_aes.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_aes \
		$(OBJDIR)/test/test_aes.o $(OBJDIR)/crypto/aes.o $(OBJDIR)/crypto/aes_ctr.o \
		$(TEST_FOUNDATION)

test_chacha20: $(TEST_FOUNDATION) $(OBJDIR)/crypto/chacha20.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_chacha20.o $(TESTDIR)/test_chacha20.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_chacha20 \
		$(OBJDIR)/test/test_chacha20.o $(OBJDIR)/crypto/chacha20.o \
		$(TEST_FOUNDATION)

test_poly1305: $(TEST_FOUNDATION) $(OBJDIR)/crypto/poly1305.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_poly1305.o $(TESTDIR)/test_poly1305.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_poly1305 \
		$(OBJDIR)/test/test_poly1305.o $(OBJDIR)/crypto/poly1305.o \
		$(TEST_FOUNDATION)

test_hmac: $(TEST_FOUNDATION) $(OBJDIR)/crypto/hmac.o $(OBJDIR)/crypto/sha256.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_hmac.o $(TESTDIR)/test_hmac.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_hmac \
		$(OBJDIR)/test/test_hmac.o $(OBJDIR)/crypto/hmac.o $(OBJDIR)/crypto/sha256.o \
		$(TEST_FOUNDATION)

test_chacha20poly1305: $(TEST_FOUNDATION) $(OBJDIR)/crypto/chacha20poly1305.o \
                       $(OBJDIR)/crypto/chacha20.o $(OBJDIR)/crypto/poly1305.o \
                       $(OBJDIR)/crypto/constant_time.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_chacha20poly1305.o $(TESTDIR)/test_chacha20poly1305.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_chacha20poly1305 \
		$(OBJDIR)/test/test_chacha20poly1305.o \
		$(OBJDIR)/crypto/chacha20poly1305.o $(OBJDIR)/crypto/chacha20.o \
		$(OBJDIR)/crypto/poly1305.o $(OBJDIR)/crypto/constant_time.o \
		$(TEST_FOUNDATION)

test_curve25519: $(TEST_FOUNDATION) $(OBJDIR)/crypto/curve25519.o \
                 $(OBJDIR)/crypto/field25519.o $(OBJDIR)/crypto/bignum.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_curve25519.o $(TESTDIR)/test_curve25519.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_curve25519 \
		$(OBJDIR)/test/test_curve25519.o $(OBJDIR)/crypto/curve25519.o \
		$(OBJDIR)/crypto/field25519.o $(OBJDIR)/crypto/bignum.o \
		$(TEST_FOUNDATION)

test_ed25519: $(TEST_FOUNDATION) $(OBJDIR)/crypto/ed25519.o \
              $(OBJDIR)/crypto/curve25519.o $(OBJDIR)/crypto/field25519.o \
              $(OBJDIR)/crypto/bignum.o $(OBJDIR)/crypto/sha512.o | $(BINDIR)
	@mkdir -p $(OBJDIR)/test
	$(NASM) $(NASMFLAGS) -o $(OBJDIR)/test/test_ed25519.o $(TESTDIR)/test_ed25519.asm
	$(LD) $(LDFLAGS) -e _main -o $(BINDIR)/test_ed25519 \
		$(OBJDIR)/test/test_ed25519.o $(OBJDIR)/crypto/ed25519.o \
		$(OBJDIR)/crypto/curve25519.o $(OBJDIR)/crypto/field25519.o \
		$(OBJDIR)/crypto/bignum.o $(OBJDIR)/crypto/sha512.o \
		$(TEST_FOUNDATION)

# Run all tests
test: test_sha256 test_sha512 test_aes test_chacha20 test_poly1305 \
      test_hmac test_chacha20poly1305 test_curve25519 test_ed25519
	@echo "Running all tests..."
	$(BINDIR)/test_sha256
	$(BINDIR)/test_sha512
	$(BINDIR)/test_aes
	$(BINDIR)/test_chacha20
	$(BINDIR)/test_poly1305
	$(BINDIR)/test_hmac
	$(BINDIR)/test_chacha20poly1305
	$(BINDIR)/test_curve25519
	$(BINDIR)/test_ed25519
	@echo "All tests passed!"

clean:
	rm -rf $(OBJDIR) $(BINDIR)
