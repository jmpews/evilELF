# evilELF
Malicious use of ELF such as .so inject, func hook and so on.

## [InejctRuntimeELF](https://github.com/jmpews/evilELF/tree/master/InjectRuntimeELF)

具体参考, [linux进程动态so注入](https://github.com/jmpews/dev2pwn/blob/master/linux%E8%BF%9B%E7%A8%8B%E5%8A%A8%E6%80%81so%E6%B3%A8%E5%85%A5.md)
实现恶意 `so` 注入, 采用直接解析 `ELF` 文件的方式, 更加具有通用性, 并以 `.gnu.hash` 进行符号查找, 适用于目前的 `ELF` 结构.
