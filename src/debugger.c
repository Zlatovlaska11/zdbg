#include "debugger.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

void attachProc(Debugger *dbg, pid_t pid) {

  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
    perror("error while attaching");
    exit(1);
  }

  dbg->pid = pid;
  dbg->breakpoint_set = 0;

  printf("[+] Attached to process %d\n", pid);

  int status;
  waitpid(pid, &status, 0);
}

void setBreakpoint(Debugger *dbg, unsigned long addr) {
  unsigned long data = ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)addr, NULL);
  if (data == -1) {
    perror("ptrace peektext failed");
    return;
  }

  // Save the original byte
  dbg->original_byte = data & 0xFF;

  // Write trap instruction (0xCC is INT 3 on x86-64)
  unsigned long trap = (data & ~0xFF) | 0xCC;
  if (ptrace(PTRACE_POKETEXT, dbg->pid, (void *)addr, (void *)trap) == -1) {
    perror("ptrace poketext failed");
    return;
  }

  dbg->breakpoint_addr = addr;
  dbg->breakpoint_set = 1;
  printf("[+] Breakpoint set at 0x%lx\n", addr);
}

unsigned long getBaseAddress(pid_t pid) {
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE *maps = fopen(maps_path, "r");
  if (!maps) {
    perror("fopen maps");
    return 0;
  }

  unsigned long base_addr = 0;
  if (fscanf(maps, "%lx-%*lx %*s %*s %*s %*s", &base_addr) == 1) {
    fclose(maps);
    return base_addr;
  }

  fclose(maps);
  return 0;
}

void setBreakpointAtMain(Debugger *dbg) {
  unsigned long base = getBaseAddress(dbg->pid);
  unsigned long main_offset = 0x1149; // from objdump
  unsigned long main_addr = base + main_offset;

  printf("[+] Setting breakpoint at main (0x%lx)...\n", main_addr);
  setBreakpoint(dbg, main_addr);
}

void continueExec(Debugger *dbg) {
  if (ptrace(PTRACE_CONT, dbg->pid, NULL, NULL) == -1) {
    fprintf(stderr, "error while continuing");
    return;
  }

  int status;
  waitpid(dbg->pid, &status, 0);

  // proces stoped
  if (WIFSTOPPED(status)) {
    int signal = WSTOPSIG(status);
    printf("[+] Process stopped with signal: %d\n", signal);

    // hit the breakpoint
    if (signal == SIGTRAP) {
      printf("[+] Breakpoint hit!\n");
      readReg(dbg);
    }
  } else if (WIFEXITED(status)) {
    printf("[+] Process exited with code: %d\n", WEXITSTATUS(status));
  }
}

void clearBreakPoint(Debugger *dbg) {
  if (!dbg->breakpoint_set) {
    fprintf(stderr, "Problem when clearing bp");
    return;
  }

  // get the modified byte with the breakpoint addr
  unsigned long data =
      ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)dbg->breakpoint_addr, NULL);

  // restore the original addr
  unsigned long restored = (data & ~0xFF) | dbg->original_byte;
  ptrace(PTRACE_POKETEXT, dbg->pid, (void *)dbg->breakpoint_addr,
         (void *)restored);

  dbg->breakpoint_set = 0;
  printf("[+] Breakpoint cleared at 0x%lx\n", dbg->breakpoint_addr);
}

void readReg(Debugger *dbg) {
  struct user_regs_struct regs;

  ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs);

  printf("\n=== Registers ===\n");
  printf("RIP: 0x%llx\n", regs.rip);
  printf("RAX: 0x%llx\n", regs.rax);
  printf("RBX: 0x%llx\n", regs.rbx);
  printf("RCX: 0x%llx\n", regs.rcx);
  printf("RDX: 0x%llx\n", regs.rdx);
  printf("RSI: 0x%llx\n", regs.rsi);
  printf("RDI: 0x%llx\n", regs.rdi);
  printf("RBP: 0x%llx\n", regs.rbp);
  printf("RSP: 0x%llx\n", regs.rsp);
  printf("\n");
}
