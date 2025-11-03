#include "stdio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/_types/_pid_t.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct Debugger {
  int pid;
  unsigned long breakpoint_addr;
  int breakpoint_set;
} Debugger;

void attachProc(Debugger *dbg, pid_t pid) {
  // PTRACE_ATTACH
  if (ptrace(16, pid, NULL, NULL) == -1) {
    perror("error while attaching");
    exit(1);
  }

  dbg->pid = pid;
  dbg->breakpoint_set = 0;

  printf("[+] Attached to process %d\n", pid);

  int status;
  waitpid(pid, &status, 0);
}

void readReg(Debugger *dbg) {
  struct user_regs_struct regs;

  // PTRACE_READ_REGS
  ptrace(12, dbg->pid, NULL, &regs);

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

int main(int argc, char *argv[]) {
  if (argc < 1) {
    perror("not enugh arguments");
  }

  int pid = atoi(argv[1]);

  printf("%i", pid);
  return 0;
}
