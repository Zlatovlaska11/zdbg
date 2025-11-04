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

pid_t spawn_process(const char *program, char *const argv[]) {
  pid_t pid = fork();

  if (pid < 0) {
    perror("fork failed");
    return -1; // Error
  }

  if (pid == 0) {
    // Child: replace with the new program
    execvp(program, argv);
    perror("execvp failed");
    _exit(1); // Use _exit to avoid flushing parent buffers
  }

  // Parent: return child's PID
  return pid;
}

int main(int argc, char *argv[]) {
  // if (argc < 2) {
  //   fprintf(stderr, "not enough args");
  //   return 1;
  // }

  char *args[] = {"./test", NULL};

  pid_t pid = spawn_process("./test", args);

  Debugger *dbg = calloc(1, sizeof(Debugger));

  attachProc(dbg, pid);
  // setBreakpointAtMain(dbg);
  //
  // readReg(dbg);

  shell(dbg);
}
