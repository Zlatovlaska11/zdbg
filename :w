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
    return -1; 
  }

  if (pid == 0) {
    execvp(program, argv);
    perror("execvp failed");
    _exit(1); 
  }

  return pid;
}

int main(int argc, char *argv[]) {

  char *args[] = {"./test", NULL};

  pid_t pid = spawn_process("./test", args);

  Debugger *dbg = calloc(1, sizeof(Debugger));

  attachProc(dbg, pid);

  shell(dbg);
}
