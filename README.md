# evilELF
Malicious use of ELF such as .so inject, func hook and so on.

## injectso

实现恶意 `so` 注入, 采用直接解析 `ELF` 文件的方式, 更加具有通用性, 并以 `.gnu.hash` 进行符号查找, 适用于目前的 `ELF` 结构.

`injectso` 参考 `glibc-2.19`, 以 `ElfW` 宏进行 `32` 和 `64` 字长兼容(目前有一个函数还没有做到 `64` 兼容, 有时间改下).

#### 参考链接:

[PWN之ELF解析](https://github.com/jmpews/dev2pwn/blob/master/PWN%E4%B9%8BELF%E8%A7%A3%E6%9E%90.md)

[linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)

