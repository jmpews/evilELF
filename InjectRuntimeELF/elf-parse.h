#include <elf.h>
#include <link.h>
#include <sys/ptrace.h>

#include <stdlib.h>
#include <stdbool.h> // bool type

// #define __ELF_NATIVE_CLASS 32

// #define ElfW(type)	_ElfW (Elf, __ELF_NATIVE_CLASS, type)
// #define _ElfW(e,w,t)	_ElfW_1 (e, w, _##t)
// #define _ElfW_1(e,w,t)	e##w##t

// eglibc-2.19/sysdeps/generic/ldsodefs.h
// #define D_PTR(map, i) ((map)->i->d_un.d_ptr + (map)->l_addr)
// #define LOOKUP_VALUE_ADDRESS(map) ((map) ? (map)->l_addr : 0)
// #define DL_SYMBOL_ADDRESS(map, ref) \
// (void *) (LOOKUP_VALUE_ADDRESS (map) + ref->st_value)

// echo | gcc -E -dM - | grep 64
// ld --verbose
#ifdef __x86_64__
#define PROGRAM_LOAD_ADDRESS 0x400000
#else
#define PROGRAM_LOAD_ADDRESS 0x08048000
#endif

#define link_map_public link_map
#include <link.h>
#undef link_map

// linker's link_map
typedef struct dyn_info
{
    // pltgot
    struct link_map_public *linkmap_public;

    // section
    long dynsym_addr;
    long dynstr_addr;
    long gnuhash_addr;

    // .gnu.hash
    unsigned int nbuckets;
    unsigned int symndx;
    unsigned int nmaskwords;
    unsigned int shift2;
    long bitmask_addr;
    long hashbuckets_addr;
    long hashvalues_addr;

    // so name;
    char *soname;
} dyn_info_t;

// read input
typedef struct elf_rt_input
{
    long vmaddr;
    pid_t pid;
} elf_rt_input_t;

typedef struct elf_arch
{
    ElfW(Ehdr) * ehdr;
    ElfW(Phdr) * phdr;
} elf_arch_t;

// runtime elf file
typedef struct elf_rt
{
    struct elf_rt_input input;
    struct elf_arch elf;
    struct dyn_info dyn;
} elf_rt_t;

long find_symbol(elf_rt_t *target, char *sym_name, char *lib_name);

void set_pid(elf_rt_t *target, pid_t pid);

bool elf_rt_read(elf_rt_input_t input, long addr, void *data, long len);

bool elf_rt_off_read(elf_rt_input_t input, long addr, void *data, long len);

char *
elf_rt_read_string(elf_rt_input_t input, long addr);

bool parse_elf(elf_rt_t *target);

bool parse_header(elf_rt_t *target);

bool parse_program_headers(elf_rt_t *target);

bool parse_segments(elf_rt_t *target);

bool parse_PT_DYNAMIC(dyn_info_t *dyninfo, elf_rt_input_t input, long dyn_addr);

bool parse_DT_SONAME(dyn_info_t *dyninfo, elf_rt_input_t input, unsigned long ndx);

bool parse_DT_GNU_HASH(dyn_info_t *dyninfo, elf_rt_input_t input, long gnuhash_addr);

bool parse_DT_PLTGOT(dyn_info_t *dyninfo, elf_rt_input_t input, long gotplt_addr);

unsigned long
dl_new_hash(const char *s);

ElfW(Sym) *
find_symbol_in_lib(dyn_info_t *dyldinfo, elf_rt_input_t input, char *sym_name);

void print_elf(elf_rt_t *target);
