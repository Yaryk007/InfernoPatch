// SPDX-License-Identifier: GPL-3.0-or-later
//
// InfernoPatch: the iOS 26 JIT region, claimed at launch.
//
// On a device with TXM, nothing in the process can make a page executable. Only
// an attached debugger can, and StikDebug does it over a breakpoint protocol
// (its universal.js, and the inferno-jit.js shipped in this app):
//
//   brk #0x69                 answered by writing a constant into x0, so it
//                             tells us the script is there and listening
//   brk #0xf00d, x16 = 1      x0 = 0, x1 = size: StikDebug allocates an RX
//                             region with debugserver `_M<size>,rx`, prepares
//                             every page of it and returns the address in x0
//   brk #0xf00d, x16 = 0      StikDebug detaches
//
// We make our own writable alias of the RX pages with vm_remap. QEMU writes
// code through that alias and runs it through the RX one, which is the split
// W^X shape tcg/region.c already uses. The RX pages stay executable after the
// detach, so the debugger is gone for the rest of the session and cannot
// freeze the app when iOS suspends it.
//
// Ported from HuskPatch's src/ios-jit/husk-ios-jit.c (GPL-2.0-or-later).

#include <TargetConditionals.h>

#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR && defined(__aarch64__)

#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ucontext.h>
#include <unistd.h>

// The trap sequences. Naked, so the compiler adds nothing around them: the
// arguments are already in x0/x1 and the debugger leaves the answer in x0.
__attribute__((naked, noinline)) static uint64_t brk_probe(uint64_t zero0, uint64_t zero1)
{
    __asm__ volatile("brk #0x69\n"
                     "ret\n");
}

__attribute__((naked, noinline)) static uint64_t brk_get_region(uint64_t addr, uint64_t size)
{
    __asm__ volatile("mov x16, #1\n"
                     "brk #0xf00d\n"
                     "ret\n");
}

__attribute__((naked, noinline)) static void brk_detach(void)
{
    __asm__ volatile("mov x16, #0\n"
                     "brk #0xf00d\n"
                     "ret\n");
}

// A brk nobody services is a SIGTRAP, which would kill the app. While one of
// ours is in flight, the handler steps over it and answers 0 instead.
static volatile sig_atomic_t expecting_trap;
static struct sigaction previous_trap;

static void trap_handler(int sig, siginfo_t *info, void *context)
{
    (void)info;
    if (expecting_trap && context) {
        ucontext_t *uc = context;
        uc->uc_mcontext->__ss.__pc += 4;
        uc->uc_mcontext->__ss.__x[0] = 0;
        return;
    }
    sigaction(sig, &previous_trap, NULL);
    raise(sig);
}

static void guard(bool on)
{
    if (on) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = trap_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTRAP, &sa, &previous_trap);
        expecting_trap = 1;
    }
    else {
        expecting_trap = 0;
        sigaction(SIGTRAP, &previous_trap, NULL);
    }
}

// Whether the kernel says a page may execute. Asked before branching into it:
// on a TXM device an unblessed page can take the process down outright, with
// no signal for the guard below to catch.
static bool page_is_executable(void *p)
{
    vm_address_t addr = (vm_address_t)p;
    vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    if (vm_region_recurse_64(mach_task_self(), &addr, &size, &depth,
                             (vm_region_recurse_info_t)&info, &count) != KERN_SUCCESS) {
        return false;
    }
    return (info.protection & VM_PROT_EXECUTE) != 0;
}

static sigjmp_buf selftest_jump;
static volatile sig_atomic_t selftest_running;

static void selftest_handler(int sig)
{
    if (selftest_running) { siglongjmp(selftest_jump, 1); }
    signal(sig, SIG_DFL);
    raise(sig);
}

// Writes `mov w0, #42; ret` through the RW alias and calls it through the RX
// one. An address and a successful remap prove nothing on their own: pages the
// debugger never prepared fault on the first instruction, deep inside QEMU.
// Only run with no debugger attached, since an attached one takes the fault
// as a stop instead of letting the guard see it.
static bool selftest(uint8_t *rw, uint8_t *rx)
{
    static const uint32_t code[2] = {0x52800540u, 0xD65F03C0u};
    memcpy(rw, code, sizeof(code));
    sys_icache_invalidate(rx, sizeof(code));
    if (memcmp(rx, code, sizeof(code)) != 0 || !page_is_executable(rx)) { return false; }

    struct sigaction sa, old_bus, old_segv, old_ill;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = selftest_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGBUS, &sa, &old_bus);
    sigaction(SIGSEGV, &sa, &old_segv);
    sigaction(SIGILL, &sa, &old_ill);

    bool ok = false;
    selftest_running = 1;
    if (sigsetjmp(selftest_jump, 1) == 0) {
        int (*fn)(void) = (int (*)(void))(void *)rx;
        ok = fn() == 42;
    }
    selftest_running = 0;

    sigaction(SIGBUS, &old_bus, NULL);
    sigaction(SIGSEGV, &old_segv, NULL);
    sigaction(SIGILL, &old_ill, NULL);
    return ok;
}

// Results, read by JIT.swift.
enum {
    INFERNO_JIT_OK = 0,
    INFERNO_JIT_NO_SCRIPT = 1,   // nothing answered the trap
    INFERNO_JIT_NO_REGION = 2,   // the universal script answered, but gave no region
    INFERNO_JIT_NO_ALIAS = 3,    // vm_remap / vm_protect / mprotect refused
    INFERNO_JIT_SELFTEST = 4,    // the region came back, but does not execute
    INFERNO_JIT_UNKNOWN = 5,     // the trap was answered with something unfamiliar
};

// Which script did it, for the log.
enum { ROUTE_NONE = 0, ROUTE_UNIVERSAL = 1, ROUTE_LEGACY = 2 };

static bool is_universal_answer(uint64_t answer)
{
    // universal.js writes E0000069 with `P0=`, which takes the register in
    // target byte order, so either byte order can come back.
    uint32_t low = (uint32_t)answer;
    return low == 0xE0000069u || low == 0x690000E0u;
}

// Upstream Inferno's iOS 26 mapping, as tcg/region.c builds it: the first
// mapping starts out executable, as TXM wants, and a mirror of it is the
// executable alias. legacy.js then prepares the mirror when it sees brk #0x69
// with the address in x0 and the size in x1.
static bool legacy_candidate(uint64_t size, vm_address_t *rw_out, vm_address_t *rx_out)
{
    void *rw = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (rw == MAP_FAILED) { return false; }
    vm_address_t rx = 0;
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    if (vm_remap(mach_task_self(), &rx, (vm_size_t)size, 0, VM_FLAGS_ANYWHERE, mach_task_self(),
                 (vm_address_t)rw, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS) {
        munmap(rw, size);
        return false;
    }
    if (mprotect((void *)rx, size, PROT_READ | PROT_EXEC) != 0) {
        munmap((void *)rx, size);
        munmap(rw, size);
        return false;
    }
    *rw_out = (vm_address_t)rw;
    *rx_out = rx;
    return true;
}

// Claims `size` bytes of executable memory from whichever StikDebug script is
// attached, with a single trap, so that legacy.js, which services exactly one
// brk #0x69 and then detaches, is not used up by a probe:
//
//   brk #0x69 with x0 = a mirror we made, x1 = size
//     legacy.js     prepares the mirror, leaves x0 alone, detaches
//     universal     answers E0000069 in x0, prepares nothing; we then ask it
//                   for a fresh region with brk #0xf00d and detach it
//     nobody        our trap guard answers 0
int inferno_jit26_claim(uint64_t size, int keep_attached,
                        uint64_t *rw_out, uint64_t *rx_out, int *route_out)
{
    *rw_out = 0;
    *rx_out = 0;
    *route_out = ROUTE_NONE;

    vm_address_t cand_rw = 0, cand_rx = 0;
    bool have_candidate = legacy_candidate(size, &cand_rw, &cand_rx);

    guard(true);
    uint64_t answer = brk_probe(have_candidate ? cand_rx : 0, have_candidate ? size : 0);
    guard(false);

    if (have_candidate && answer == cand_rx) {
        // legacy.js prepared the mirror and has already detached.
        *route_out = ROUTE_LEGACY;
        if (mprotect((void *)cand_rw, size, PROT_READ | PROT_WRITE) != 0) {
            munmap((void *)cand_rx, size);
            munmap((void *)cand_rw, size);
            return INFERNO_JIT_NO_ALIAS;
        }
        if (!selftest((uint8_t *)cand_rw, (uint8_t *)cand_rx)) {
            munmap((void *)cand_rx, size);
            munmap((void *)cand_rw, size);
            return INFERNO_JIT_SELFTEST;
        }
        *rw_out = cand_rw;
        *rx_out = cand_rx;
        return INFERNO_JIT_OK;
    }

    if (have_candidate) {
        munmap((void *)cand_rx, size);
        munmap((void *)cand_rw, size);
    }
    if (answer == 0) { return INFERNO_JIT_NO_SCRIPT; }
    if (!is_universal_answer(answer)) { return INFERNO_JIT_UNKNOWN; }

    *route_out = ROUTE_UNIVERSAL;
    void *rx = NULL;
    for (int attempt = 0; attempt < 3 && !rx; attempt++) {
        if (attempt) { usleep(50 * 1000); }
        guard(true);
        rx = (void *)(uintptr_t)brk_get_region(0, size);
        guard(false);
    }
    if (!rx) { return INFERNO_JIT_NO_REGION; }

    vm_address_t rw = 0;
    vm_prot_t cur = VM_PROT_NONE, max = VM_PROT_NONE;
    kern_return_t kr = vm_remap(mach_task_self(), &rw, (vm_size_t)size, 0, VM_FLAGS_ANYWHERE,
                                mach_task_self(), (vm_address_t)rx, FALSE, &cur, &max,
                                VM_INHERIT_NONE);
    if (kr == KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(), rw, (vm_size_t)size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
        if (kr != KERN_SUCCESS) { vm_deallocate(mach_task_self(), rw, (vm_size_t)size); }
    }
    if (kr != KERN_SUCCESS) { return INFERNO_JIT_NO_ALIAS; }

    // Detach before the self-test: once the debugger is gone, a fault is a
    // signal the guard can catch, not a stop nobody answers.
    if (!keep_attached) {
        guard(true);
        brk_detach();
        guard(false);
        if (!selftest((uint8_t *)rw, rx)) {
            vm_deallocate(mach_task_self(), rw, (vm_size_t)size);
            vm_deallocate(mach_task_self(), (vm_address_t)rx, (vm_size_t)size);
            return INFERNO_JIT_SELFTEST;
        }
    }

    *rw_out = (uint64_t)rw;
    *rx_out = (uint64_t)(uintptr_t)rx;
    return INFERNO_JIT_OK;
}

#endif
