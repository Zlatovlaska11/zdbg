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
  // Read regions to find the executable code section
  char line[256];
  while (fgets(line, sizeof(line), maps)) {
    unsigned long start, end, offset;
    char perms[5];
    char filename[256];
    
    if (sscanf(line, "%lx-%lx %s %lx %*s %*s %255s", &start, &end, perms, &offset, filename) >= 4) {
      // Look for executable region with non-zero offset (the actual code)
      if (perms[2] == 'x' && offset > 0) {
        base_addr = start;
        printf("[*] Found executable section at 0x%lx (file offset: 0x%lx)\n", start, offset);
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

      setBreakpoint(dbg, addrFull);
    } else if (strcmp(input, "clearbreak") == 0) {
      clearBreakPoint(dbg);
    } else if (strcmp(input, "help") == 0) {
      printf("Commands:\n");
      printf("  regs           - Show registers\n");
      printf(
          "  break <addr>   - Set breakpoint at hex offset (from objdump)\n");
      printf("  clearbreak     - Clear current breakpoint\n");
      printf("  continue (c)   - Continue execution\n");
      printf("  quit (q)       - Detach and quit\n");
    } else if (strlen(input) > 0) {
      printf("Unknown command: %s\n", input);
    }
  }
}
