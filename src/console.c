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
      unsigned long addr = strtoul(input + 6, NULL, 16);
      unsigned long base = getBaseAddress(dbg->pid);
      unsigned long main_offset = addr;
      unsigned long addrFull = base + main_offset;

      setBreakpoint(dbg, addrFull);
    } else if (strcmp(input, "clearbreak") == 0) {
      clearBreakPoint(dbg);
    } else if (strcmp(input, "help") == 0) {
      printf("Commands:\n");
      printf("  regs           - Show registers\n");
      printf("  break <addr>   - Set breakpoint at hex address\n");
      printf("  clearbreak     - Clear current breakpoint\n");
      printf("  continue (c)   - Continue execution\n");
      printf("  quit (q)       - Detach and quit\n");
    } else if (strlen(input) > 0) {
      printf("Unknown command: %s\n", input);
    }
  }
}
