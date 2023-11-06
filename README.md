# API-Hashing

A basic exemple of the API-Hashing method used by Red Teamers but also by malwares developers in C++ to avoid IAT entries.

# How to compile

* Install LLVM for Windows: [https://github.com/llvm/llvm-project/releases/download/llvmorg-16.0.0/LLVM-16.0.0-win64.exe](https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.4/LLVM-17.0.4-win64.exe)
* Do not forget to check the "Add LLVM to the system PATH for current user" during the installation.
```
clang++ *.cpp -o output.exe
```

Based on:

* https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
* https://github.com/LloydLabs/Windows-API-Hashing
* And another source that I actually don't remember (I will update it later when I will found the repository again).
