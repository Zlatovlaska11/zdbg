#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct Debugger {
  int pid;
  unsigned long breakpoint_addr;
  unsigned char original_byte;
  int breakpoint_set;
} Debugger;

void attachProc(Debugger *dbg, pid_t pid);
void setBreakpoint(Debugger *dbg, uint64_t bp);
void readReg(Debugger *dbg);
void continueExec(Debugger *dbg);
void clearBreakPoint(Debugger *dbg);
void setBreakpointAtMain(Debugger *dbg);
unsigned long getBaseAddress(pid_t pid);

#endif
