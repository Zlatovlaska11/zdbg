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

  printf("[*] Read data at 0x%lx: 0x%lx\n", addr, data);
  printf("[*] First byte (instruction): 0x%02x\n", (unsigned char)(data & 0xFF));

  // Save the original byte
  dbg->original_byte = data & 0xFF;

  // Write trap instruction (0xCC is INT 3 on x86-64)
  unsigned long trap = (data & ~0xFF) | 0xCC;
  if (ptrace(PTRACE_POKETEXT, dbg->pid, (void *)addr, (void *)trap) == -1) {
    perror("ptrace poketext failed");
    return;
  }

  // Verify it was written
  unsigned long verify = ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)addr, NULL);

  dbg->breakpoint_addr = addr;
  dbg->breakpoint_set = 1;
  printf("[+] Breakpoint set at 0x%lx\n", addr);
}


void singleStep(Debugger *dbg) {
  if (ptrace(PTRACE_SINGLESTEP, dbg->pid, NULL, NULL) == -1) {
    perror("ptrace singlestep failed");
    return;
  }

  int status;
  waitpid(dbg->pid, &status, 0);
}

void continueExec(Debugger *dbg) {
  printf("[*] About to continue process...\n");
  if (ptrace(PTRACE_CONT, dbg->pid, NULL, NULL) == -1) {
    fprintf(stderr, "error while continuing");
    return;
  }

  int status;
  printf("[*] Waiting for process to stop...\n");
  waitpid(dbg->pid, &status, 0);


  // process stopped
  if (WIFSTOPPED(status)) {
    int signal = WSTOPSIG(status);
    printf("[+] Process stopped with signal: %d\n", signal);

    // hit the breakpoint
    if (signal == SIGTRAP) {
      printf("[+] Breakpoint hit!\n");
      readReg(dbg);
      
      if (dbg->breakpoint_set) {
        printf("[+] Restoring breakpoint...\n");
        
        clearBreakPoint(dbg);
        
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, dbg->pid, NULL, &regs);
        
        printf("[+] Single-stepping over instruction...\n");
        singleStep(dbg);
        
        setBreakpoint(dbg, dbg->breakpoint_addr);
      }
    } else {
      printf("[-] Unexpected signal: %d\n", signal);
    }
  } else if (WIFEXITED(status)) {
    printf("[+] Process exited with code: %d\n", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    printf("[+] Process terminated by signal: %d\n", WTERMSIG(status));
  }
}

void clearBreakPoint(Debugger *dbg) {
  if (!dbg->breakpoint_set) {
    fprintf(stderr, "Problem when clearing bp");
    return;
  }

  unsigned long data =
      ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)dbg->breakpoint_addr, NULL);

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
