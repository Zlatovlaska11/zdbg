## Z-DBG

A basic debugger that can attach to running processes, set breakpoints, and inspect CPU registers.

## What it does

- Attaches to a running program
- Sets breakpoints at specific memory addresses
- Pauses execution and shows register values when breakpoints are hit
- Continues execution

## Requirements

- Linux or Unix system (macOS requires modifications)
- GCC compiler
- A compiled C program to debug

## Quick Start

### 1. Compile your test program

```bash
gcc -g test.c -o test
```

The `-g` flag is important—it includes debug symbols.

### 2. Find the main function address

```bash
objdump -d ./test | grep "<main>:" | awk '{print $1}'
```

This prints something like: `0000000000001149`

Save this number.

### 3. Compile the debugger

```bash
gcc -g debugger.c main.c -o debugger
```

### 4. Run your test program in the background

```bash
./test &
```

Note the PID it prints (e.g., `[1] 12345`).

### 5. Start the debugger

```bash
sudo ./debugger 12345
```

Replace `12345` with the PID from step 4.

### 6. Use the debugger

```
(dbg) help              # See all commands
(dbg) continue          # Run until breakpoint
(dbg) regs              # Show register values
(dbg) break 0x8098      # Sets the breakpoint addr
(dbg) quit              # Exit
```

## Example Session

```bash
# Terminal 1: Run your program
$ ./test &
[1] 12345

# Terminal 2: Start debugger
$ ./debugger 12345
[+] Attached to process 12345
(dbg) break 0x1149
(dbg) continue
[+] Continuing execution...
[+] Breakpoint hit!
=== Registers ===
RIP: 0x555555561149
RAX: 0x0
RBX: 0x0
...
(dbg) quit
[+] Detached from process 12345
```

## Commands

- `continue` or `c` - Run the program
- `regs` - Show CPU registers
- `break <address>` - Set breakpoint at hex address
- `clearbreak` - Remove current breakpoint
- `help` - Show all commands
- `quit` or `q` - Exit debugger

## How it works

1. `ptrace()` is a system call that lets one process control another
2. When we set a breakpoint, we replace an instruction with a trap (`0xCC`)
3. When the CPU hits the trap, the OS pauses the program
4. We can then inspect memory and registers
5. We restore the original instruction and continue

