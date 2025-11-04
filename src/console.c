#include "debugger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void Executor(char *line, Debugger *dbg) {

  char *args = strtok(line, " ");

  if (strcmp("sreg", line)) {
    readReg(dbg);
  }
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
  // Read the first executable region (r-xp means readable and executable)
  char line[256];
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end;
    char perms[5];

    if (sscanf(line, "%lx-%lx %s", &start, &end, perms) == 3) {
      // Look for first executable region
      if (perms[2] == 'x') {
        base_addr = start;
        break;
      }
    }
  }

  fclose(maps);
  return base_addr;
}

void shell(Debugger *dbg) {
  char input[256];

  while (1) {
    printf("(dbg) ");
    if (fgets(input, sizeof(input), stdin) == NULL)
      break;

    // Remove newline
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n')
      input[len - 1] = '\0';

    if (strcmp(input, "quit") == 0 || strcmp(input, "q") == 0) {
      break;
    } else if (strcmp(input, "regs") == 0) {
      readReg(dbg);
    } else if (strcmp(input, "continue") == 0 || strcmp(input, "c") == 0) {
      continueExec(dbg);
    } else if (strncmp(input, "break ", 6) == 0) {
      unsigned long offset = strtoul(input + 6, NULL, 16);
      unsigned long base = getBaseAddress(dbg->pid);

      if (base == 0) {
        printf("[-] Failed to get base address\n");
        continue;
      }

      unsigned long addrFull = base + offset;
      printf("[*] Base: 0x%lx, Offset: 0x%lx, Full Address: 0x%lx\n", base,
             offset, addrFull);

      addBreakpoint(dbg, addrFull);
    } else if (strcmp(input, "breaks") == 0) {
      listBreakpoints(dbg);
    } else if (strncmp(input, "delete ", 7) == 0) {
      int index = atoi(input + 7);
      deleteBreakpoint(dbg, index);

    } else if (strncmp(input, "read ", 5) == 0) {
      unsigned long addr = strtoul(input + 5, NULL, 16);
      readMemory(dbg, addr, 64);
    } else if (strcmp(input, "vars") == 0) {
      listVariables(dbg->pid, "./test"); // pass your binary path

    } else if (strncmp(input, "readint ", 8) == 0) {
      unsigned long addr = strtoul(input + 8, NULL, 16);
      unsigned int val = readInt(dbg, addr);
      printf("[*] Int at 0x%lx: 0x%08x (%d)\n", addr, val, (int)val);
    } else if (strncmp(input, "stack ", 6) == 0) {
      int offset = atoi(input + 6);
      readStack(dbg, offset);
    } else if (strcmp(input, "help") == 0) {
      printf("Commands:\n");
      printf("  regs                - Show all registers\n");
      printf("  break <addr>        - Set breakpoint at hex offset\n");
      printf("  clearbreak          - Clear current breakpoint\n");
      printf("  continue (c)        - Continue execution\n");
      printf("  read <addr>         - Read 64 bytes from hex address\n");
      printf("  readint <addr>      - Read 4-byte integer from address\n");
      printf("  readlong <addr>     - Read 8-byte long from address\n");
      printf("  stack <offset>      - Read from RBP + offset\n");
      printf("  quit (q)            - Detach and quit\n");
    } else if (strlen(input) > 0) {
      printf("Unknown command: %s\n", input);
    }
  }
}
