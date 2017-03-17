#include "utils.h"
#include "elf-parse.h"

void set_pid(elf_rt_t *target, pid_t pid)
{
    target->input.pid = pid;
    target->input.vmaddr = PROGRAM_LOAD_ADDRESS;
}

bool elf_rt_read(elf_rt_input_t input, long addr, void *data, long len)
{
    return ptrace_read(input.pid, addr, data, len);
}

bool elf_rt_off_read(elf_rt_input_t input, long addr, void *data, long len)
{
    return ptrace_read(input.pid, addr + input.vmaddr, data, len);
}
char *
elf_rt_read_string(elf_rt_input_t input, long addr)
{
    return ptrace_read_string(input.pid, addr);
}

bool parse_elf(elf_rt_t *target)
{
    parse_header(target);
    parse_segments(target);
    return true;
}

bool parse_header(elf_rt_t *target)
{
    ElfW(Ehdr) *ehdr = malloc(sizeof(ElfW(Ehdr)));
    elf_rt_off_read(target->input, 0, ehdr, sizeof(ElfW(Ehdr)));
    target->elf.ehdr = ehdr;
    parse_program_headers(target);
    return true;
}

bool parse_program_headers(elf_rt_t *target)
{
    ElfW(Ehdr) *ehdr = target->elf.ehdr;
    long phdr_off = 0;
    ElfW(Phdr) * phdrs, *tmp;
    unsigned int phnum = ehdr->e_phnum;
    phdr_off = ehdr->e_phoff;
    phdrs = tmp = (ElfW(Phdr) *)malloc(phnum * sizeof(ElfW(Phdr)));
    /*simple way */
    /*elf_rt_off_read(target->input, phdr_off, phdrs, phnum * sizeof(ElfW(Phdr)) */
    for (int i = 0; i < phnum; i++)
    {
        elf_rt_off_read(target->input, phdr_off, (long)tmp, sizeof(ElfW(Phdr)));
        phdr_off += sizeof(ElfW(Phdr));
        tmp++;
    }
    target->elf.phdr = phdrs;
    return true;
}

bool parse_segments(elf_rt_t *target)
{
    ElfW(Ehdr) *ehdr = target->elf.ehdr;
    ElfW(Phdr) *phdr = target->elf.phdr;
    unsigned int phnum = ehdr->e_phnum;
    for (int i = 0; i < phnum; i++)
    {
        switch (phdr->p_type)
        {
        case PT_DYNAMIC:
            parse_PT_DYNAMIC(&(target->dyn), target->input, phdr->p_vaddr);
            break;
        case PT_LOAD:
            break;
        default:
            break;
        }
        phdr++;
    }
}

bool parse_PT_DYNAMIC(dyn_info_t *dyninfo, elf_rt_input_t input, long dyn_addr)
{
    ElfW(Dyn) dyn;
    unsigned long dtsoname_ndx = 0;
    elf_rt_read(input, dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    while (dyn.d_tag)
    {
        switch (dyn.d_tag)
        {
        case DT_PLTGOT:
            parse_DT_PLTGOT(dyninfo, input, dyn.d_un.d_ptr);
            break;
        case DT_GNU_HASH:
            dyninfo->gnuhash_addr = dyn.d_un.d_ptr;
            parse_DT_GNU_HASH(dyninfo, input, dyn.d_un.d_ptr);
            break;
        case DT_SYMTAB:
            dyninfo->dynsym_addr = dyn.d_un.d_ptr;
            break;
        case DT_STRTAB:
            dyninfo->dynstr_addr = dyn.d_un.d_ptr;
            break;
        case DT_SONAME:
            dtsoname_ndx = dyn.d_un.d_val;
            break;
        default:
            break;
        }
        dyn_addr += sizeof(ElfW(Dyn));
        elf_rt_read(input, dyn_addr, &dyn, sizeof(ElfW(Dyn)));
    }
    if(dtsoname_ndx)
        parse_DT_SONAME(dyninfo, input, dtsoname_ndx);
    return true;
}

bool parse_DT_SONAME(dyn_info_t *dyninfo, elf_rt_input_t input, unsigned long ndx)
{
    long dynstr_addr = dyninfo->dynstr_addr + ndx;
    char *soname = elf_rt_read_string(input, dynstr_addr);
    dyninfo->soname = soname;
    return true;
}

bool parse_DT_GNU_HASH(dyn_info_t *dyninfo, elf_rt_input_t input, long gnuhash_addr)
{
    unsigned int nbuckets, symndx, nmaskwords, shift2;
    unsigned int *gnuhash_header = malloc(4 * sizeof(unsigned int));
    long hashbuckets_addr, hashvalues_addr;

    elf_rt_read(input, gnuhash_addr, gnuhash_header, 4 * sizeof(unsigned int));
    dyninfo->nbuckets = gnuhash_header[0];
    dyninfo->symndx = gnuhash_header[1];
    dyninfo->nmaskwords = gnuhash_header[2];
    dyninfo->shift2 = gnuhash_header[3];

    dyninfo->bitmask_addr = gnuhash_addr + 4 * sizeof(unsigned int);
    dyninfo->hashbuckets_addr = dyninfo->bitmask_addr + dyninfo->nmaskwords * sizeof(long);
    dyninfo->hashvalues_addr = dyninfo->hashbuckets_addr + dyninfo->nbuckets * sizeof(unsigned int);
    return true;
}

bool parse_DT_PLTGOT(dyn_info_t *dyninfo, elf_rt_input_t input, long gotplt_addr)
{
    long linkmap_public_addr;
    struct link_map_public *linkmap_public = malloc(sizeof(struct link_map_public));

    /*now just read first link_map item, link_map locate at second of .gotplt */
    elf_rt_read(input, gotplt_addr + sizeof(long), &linkmap_public_addr, sizeof(long));
    elf_rt_read(input, linkmap_public_addr, linkmap_public, sizeof(struct link_map_public));

    dyninfo->linkmap_public = linkmap_public;
    return true;
}

//eglibc-2.19/elf/dl-lookup.c
unsigned long
dl_new_hash(const char *s)
{
    unsigned long h = 5381;
    unsigned char c;
    for (c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

/*seach symbol name in elf(so) */
ElfW(Sym) *
    find_symbol_in_lib(dyn_info_t *dyldinfo, elf_rt_input_t input, char *sym_name)
{
    unsigned long c;
    unsigned int new_hash, h2;
    unsigned int hb1, hb2;
    unsigned long n;
    Elf_Symndx symndx;
    long bitmask_word;
    long addr;
    long sym_addr, hash_addr;
    char *symstr;
    ElfW(Sym) *sym = malloc(sizeof(ElfW(Sym)));

    new_hash = dl_new_hash(sym_name);

    /*new-hash % __ELF_NATIVE_CLASS */
    hb1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    hb2 = (new_hash >> dyldinfo->shift2) & (__ELF_NATIVE_CLASS - 1);

    printf("[*] start gnu hash search:\n\tnew_hash: 0x%x(%u)\n", sym_name, new_hash, new_hash);

    /*ELFCLASS size */
    //__ELF_NATIVE_CLASS

    /* nmaskwords must be power of 2, so that allows the modulo operation */
    /*((new_hash / __ELF_NATIVE_CLASS) % maskwords) */
    n = (new_hash / __ELF_NATIVE_CLASS) & (dyldinfo->nmaskwords - 1);
    printf("\tn: %lu\n", n);

    /*Use hash to quickly determine whether there is the symbol we need */
    addr = dyldinfo->bitmask_addr + n * sizeof(long);
    elf_rt_read(input, addr, &bitmask_word, sizeof(long));
    /*eglibc-2.19/elf/dl-loopup.c:236 */
    /*https://blogs.oracle.com/ali/entry/gnu_hash_elf_sections */
    /*different method same result */
    if (((bitmask_word >> hb1) & (bitmask_word >> hb2) & 1) == 0)
        return NULL;

    /*The first index of `.dynsym` to the bucket .dynsym */
    addr = dyldinfo->hashbuckets_addr + (new_hash % dyldinfo->nbuckets) * sizeof(Elf_Symndx);
    elf_rt_read(input, addr, &symndx, sizeof(unsigned int));
    printf("\thash buckets index: 0x%x(%u), first dynsym index: 0x%x(%u)\n", (new_hash % dyldinfo->nbuckets), (new_hash % dyldinfo->nbuckets), symndx, symndx);

    if (symndx == 0)
        return NULL;

    sym_addr = dyldinfo->dynsym_addr + symndx * sizeof(ElfW(Sym));
    hash_addr = dyldinfo->hashvalues_addr + (symndx - dyldinfo->symndx) * sizeof(unsigned int);

    printf("[*] start bucket search:\n");
    do
    {
        elf_rt_read(input, hash_addr, &h2, sizeof(unsigned int));
        printf("\th2: 0x%x(%u)\n", h2, h2);
        /*1. hash value same */
        if (((h2 ^ new_hash) >> 1) == 0)
        {

            sym_addr = dyldinfo->dynsym_addr + ((dyldinfo->symndx + (hash_addr - dyldinfo->hashvalues_addr) / sizeof(Elf32_Word)) * sizeof(ElfW(Sym)));
            /*read ElfW(Sym) */
            elf_rt_read(input, sym_addr, sym, sizeof(ElfW(Sym)));
            addr = dyldinfo->dynstr_addr + sym->st_name;
            /*read string */
            symstr = elf_rt_read_string(input, addr);

            /*2. name same */
            if (symstr && (!strcmp(sym_name, symstr)))
            {
                free(symstr);
                return sym;
            }
            free(symstr);
        }
        hash_addr += sizeof(unsigned int);
    } while ((h2 & 1u) == 0); // search in same bucket
    return NULL;
}

long find_symbol(elf_rt_t *target, char *sym_name, char *lib_name)
{
    struct link_map_public *linkmap_addr;
    struct link_map_public linkmap;
    long sym_addr = 0;
    char *soname;
    ElfW(Sym) * sym;
    dyn_info_t dyninfo;

    printf("[*] start search \'%s\':\n", sym_name);

    linkmap_addr = target->dyn.linkmap_public->l_next;

    while (!sym_addr && linkmap_addr)
    {
        elf_rt_read(target->input, (long)linkmap_addr, &linkmap, sizeof(struct link_map_public));
        linkmap_addr = linkmap.l_next;
        soname = elf_rt_read_string(target->input, (long)linkmap.l_name);
        if (!soname || !soname[0])
            continue;

        /*compare libname if its not NULL */
        if (lib_name)
            if (strcmp(lib_name, soname) != 0)
                continue;

        printf("[+] search libaray path: %s\n", soname);
        parse_PT_DYNAMIC(&dyninfo, target->input, linkmap.l_ld);
        sym = find_symbol_in_lib(&dyninfo, target->input, sym_name);
        if (sym)
        {
            sym_addr = sym->st_value + linkmap.l_addr;
            printf("[+] Found \'%s\' at %p\n", sym_name, sym_addr);
            return sym_addr;
        }
    }

    printf("[-] Not found \'%s\'", sym_name);
    return 0;
}
