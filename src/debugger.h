#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct BreakPoint {
  unsigned long bp_addr;
  unsigned char origin_byte;
} BreakPoint;

typedef struct Debugger {
  int pid;
  unsigned long breakpoint_addr;
  unsigned char original_byte;
  int breakpoint_set;
  BreakPoint breakpoints[100];
  int breakpoint_count;
  int last_hit_index;  // NEW: Track which breakpoint just fired
} Debugger;

void attachProc(Debugger *dbg, pid_t pid);
void setBreakpoint(Debugger *dbg, unsigned long addr, BreakPoint *bp);
void readReg(Debugger *dbg);
void continueExec(Debugger *dbg);
void clearBreakPoint(Debugger *dbg, BreakPoint *bp);
void setBreakpointAtMain(Debugger *dbg);
unsigned int readInt(Debugger *dbg, unsigned long addr);
void readStack(Debugger *dbg, int offset);
void readMemory(Debugger *dbg, unsigned long addr, int size);
void listVariables(pid_t pid, const char *binary_path);
void deleteBreakpoint(Debugger *dbg, int index);
void listBreakpoints(Debugger *dbg);
int addBreakpoint(Debugger *dbg, unsigned long addr);

#endif
