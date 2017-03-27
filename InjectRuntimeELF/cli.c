#include "cli.h"
#include "Zz.h"
#include "elf-parse.h"
#include "utils.h"

#define _print_line_sep (printf("--------------------------------------------------------------\n"))

void print_welcome()
{
    printf(GRN);
    _print_line_sep;
    printf("%s - (%s) - by %s\n", PROGRAM_NAME, PROGRAM_VER, PROGRAM_AUTHOR);
    _print_line_sep;
    printf(RESET);
}


void print_usage()
{
  printf(GRN);
  printf("usage: sudo ./inject <pid> </path/evil.so>");
  printf(RESET);
}