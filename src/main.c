#include "console.h"
#include "debugger.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "not enough args");
    return 1;
  }

  int pid = atoi(argv[1]);

  Debugger *dbg = calloc(1, sizeof(Debugger));

  attachProc(dbg, pid);
  // setBreakpointAtMain(dbg);
  //
  // readReg(dbg);

  shell(dbg);
}
