#ifndef utils_h
#define utils_h
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include <stdbool.h> // bool type

void ptrace_attach(int pid);
void ptrace_cont(int pid);
void ptrace_detach(int pid);
bool ptrace_read(int pid, unsigned long addr, void *data, unsigned int len);
char *
ptrace_read_string(int pid, unsigned long addr);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
#endif