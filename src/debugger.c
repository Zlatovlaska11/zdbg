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

int addBreakpoint(Debugger *dbg, unsigned long addr) {
  if (dbg->breakpoint_count >= 100) {
    printf("[-] Max breakpoints reached\n");
    return -1;
  }

  // Check if this address already has a breakpoint
  for (int i = 0; i < dbg->breakpoint_count; i++) {
    if (dbg->breakpoints[i].bp_addr == addr) {
      printf("[-] Breakpoint already exists at 0x%lx\n", addr);
      return -1;
    }
  }

  BreakPoint *bp = &dbg->breakpoints[dbg->breakpoint_count];
  setBreakpoint(dbg, addr, bp);
  dbg->breakpoint_count++;

  return 0;
}

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

void setBreakpoint(Debugger *dbg, unsigned long addr, BreakPoint *bp) {
  unsigned long data = ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)addr, NULL);
  if (data == -1) {
    perror("ptrace peektext failed");
    return;
  }

  printf("[*] Read data at 0x%lx: 0x%lx\n", addr, data);
  printf("[*] First byte (instruction): 0x%02x\n",
         (unsigned char)(data & 0xFF));

  // Save the original byte
  bp->origin_byte = data & 0xFF;

  // Write trap instruction (0xCC is INT 3 on x86-64)
  unsigned long trap = (data & ~0xFF) | 0xCC;
  if (ptrace(PTRACE_POKETEXT, dbg->pid, (void *)addr, (void *)trap) == -1) {
    perror("ptrace poketext failed");
    return;
  }

  unsigned long verify = ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)addr, NULL);

  bp->bp_addr = addr;
  dbg->breakpoint_set = 1;
  dbg->breakpoint_count++;
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

    // hit a breakpoint
    if (signal == SIGTRAP) {
      printf("[+] Breakpoint hit!\n");
      readReg(dbg);

      if (dbg->breakpoint_count > 0) {
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs);

        // Find which breakpoint was hit
        int hit_index = -1;
        for (int i = 0; i < dbg->breakpoint_count; i++) {
          if (dbg->breakpoints[i].bp_addr == regs.rip - 1) {
            hit_index = i;
            break;
          }
        }

        if (hit_index != -1) {
          printf("[+] Handling breakpoint %d at 0x%lx\n", hit_index,
                 dbg->breakpoints[hit_index].bp_addr);

          regs.rip -= 1;
          ptrace(PTRACE_SETREGS, dbg->pid, NULL, &regs);

          clearBreakPoint(dbg, &dbg->breakpoints[hit_index]);

          singleStep(dbg);

          setBreakpoint(dbg, dbg->breakpoints[hit_index].bp_addr,
                        &dbg->breakpoints[hit_index]);

          printf("[+] Continuing past breakpoint...\n");
          if (ptrace(PTRACE_CONT, dbg->pid, NULL, NULL) == -1) {
            fprintf(stderr, "error while continuing");
            return;
          }

          printf("[*] Waiting for next event...\n");
          waitpid(dbg->pid, &status, 0);

          if (WIFSTOPPED(status)) {
            int next_signal = WSTOPSIG(status);
            printf("[+] Process stopped with signal: %d\n", next_signal);
            if (next_signal == SIGTRAP) {
              printf("[+] Hit another breakpoint!\n");
              readReg(dbg);
            }
          } else if (WIFEXITED(status)) {
            printf("[+] Process exited with code: %d\n", WEXITSTATUS(status));
          } else if (WIFSIGNALED(status)) {
            printf("[+] Process terminated by signal: %d\n", WTERMSIG(status));
          }
        }
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

void clearBreakPoint(Debugger *dbg, BreakPoint *bp) {
  if (!dbg->breakpoint_set) {
    fprintf(stderr, "Problem when clearing bp");
    return;
  }

  unsigned long data =
      ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)bp->bp_addr, NULL);

  unsigned long restored = (data & ~0xFF) | bp->origin_byte;
  ptrace(PTRACE_POKETEXT, dbg->pid, (void *)bp->bp_addr, (void *)restored);

  printf("[+] Breakpoint cleared at 0x%lx\n", bp->bp_addr);
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

unsigned long readByte(Debugger *dbg, unsigned long memory_addr) {
  unsigned long data =
      ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)memory_addr, NULL);

  if (data == -1) {
    fprintf(stderr, "error while reading memory at %lx", memory_addr);
    return -1;
  }

  unsigned int offset = memory_addr % sizeof(unsigned long);
  return (data >> (offset * 8)) & 0xFF;
}

unsigned int readInt(Debugger *dbg, unsigned long addr) {
  unsigned long aligned_addr = addr & ~(sizeof(unsigned long) - 1);
  unsigned long data =
      ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)aligned_addr, NULL);

  if (data == -1) {
    fprintf(stderr, "error while reading memory at %lx", addr);
    return -1;
  }

  // Calculate offset within the aligned word
  unsigned int offset = addr % sizeof(unsigned long);
  return ((data >> (offset * 8)) & 0xFFFFFFFF);
}

void readMemory(Debugger *dbg, unsigned long addr, int size) {
  printf("\n=== Memory at 0x%lx (size: %d) ===\n", addr, size);

  for (int i = 0; i < size; i += 8) {
    unsigned long data =
        ptrace(PTRACE_PEEKTEXT, dbg->pid, (void *)(addr + i), NULL);
    if (data == -1) {
      perror("ptrace peektext failed");
      return;
    }

    printf("0x%lx: ", addr + i);
    printf("0x%016lx ", data);

    printf("| ");
    for (int j = 0; j < 8 && i + j < size; j++) {
      unsigned char byte = (data >> (j * 8)) & 0xFF;
      if (byte >= 32 && byte <= 126) {
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
  }
  printf("\n");
}

void readStack(Debugger *dbg, int offset) {
  struct user_regs_struct regs;
  ptrace(PTRACE_GETREGS, dbg->pid, NULL, &regs);

  unsigned long addr = regs.rbp + offset;
  printf("[*] Reading from RBP + %d (0x%lx)\n", offset, addr);

  readMemory(dbg, addr, 32);
}

// DEBUG REASONS
void listVariables(pid_t pid, const char *binary_path) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd),
           "readelf --debug-dump=info %s | grep -A5 'DW_TAG_variable'",
           binary_path);

  FILE *fp = popen(cmd, "r");
  if (!fp) {
    perror("popen failed");
    return;
  }

  char line[256];
  printf("\n=== Variables ===\n");
  while (fgets(line, sizeof(line), fp)) {
    printf("%s", line);
  }

  pclose(fp);
}

void listBreakpoints(Debugger *dbg) {
  if (dbg->breakpoint_count == 0) {
    printf("[-] No breakpoints set\n");
    return;
  }

  printf("\n=== Breakpoints (%d total) ===\n", dbg->breakpoint_count);
  for (int i = 0; i < dbg->breakpoint_count; i++) {
    printf("%d: 0x%lx\n", i, dbg->breakpoints[i].bp_addr);
  }
  printf("\n");
}

void deleteBreakpoint(Debugger *dbg, int index) {
  if (index < 0 || index >= dbg->breakpoint_count) {
    printf("[-] Invalid breakpoint index: %d\n", index);
    return;
  }

  clearBreakPoint(dbg, &dbg->breakpoints[index]);

  for (int i = index; i < dbg->breakpoint_count - 1; i++) {
    dbg->breakpoints[i] = dbg->breakpoints[i + 1];
  }

  dbg->breakpoint_count--;
  printf("[+] Breakpoint %d deleted\n", index);
}
