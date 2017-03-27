#ifndef cli_c
#define cli_c

#include "Zz.h"
#include <stdio.h>

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

//Important!!!
// STDERR before STDOUT, because sync
#define Xdebug(fmt, ...) \
        do { if (GLOBAL_DEBUG) fprintf(stdout, RESET fmt, \
        __VA_ARGS__); } while (0)
#define Sdebug(MSG) Xdebug("%s", MSG)

#define Xerror(fmt, ...) \
        do { fprintf(stderr, RED "[!] " "%s:%d:%s(): " fmt RESET, __FILE__, \
        __LINE__, __func__, __VA_ARGS__); } while (0)
#define Serror(MSG) Xerror("%s", MSG)
//#define xinfo(str) printf(GRN "[*] " "%s" "\n" RESET, str)
//#define xinfo(X) {printf(RESET "[*] "); X; printf("\n");}
#define Xinfo(fmt, ...) \
        do { fprintf(stderr, RESET "[*] " fmt "\n", \
        __VA_ARGS__); } while (0)
#define Sinfo(MSG) Xinfo("%s", MSG)

void print_welcome();
void print_usage();

#endif /* cli_hpp */
