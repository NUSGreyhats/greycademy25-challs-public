# Greycademy 2025 practice challenge list

### Welcome

| Done? | Name | Challenge Details | Estimated Difficulty (1-5) | Port Number |
| ----- | ---- | ----------------- | -------------------------- | ----------- |
|       |      |                   |                            |             |

### pwn

| Done? | Name                  | Challenge Details                              | Estimated Difficulty (1-5) | Port Number |
| ----- | --------------------- | ---------------------------------------------- | -------------------------- | ----------- |
| yes | blast from the past     | buffer overflow and ret2shellcode              | 3                          | 33000       |
| yes | sunshinefactory         | overwrite least significant byte of a function pointer to call win function | 5 | 33001 |
| yes | bof-school | basic buffer overflow | 1 | 33002 |
| yes | copypasta of the day | ROP | 2 | 33003 |
| yes | moonlight factory | printf vuln to leak canary and libc, ret2libc | 4 | 33004 |

### Web

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------- | - | - |
| yes | How to solve a CTF challenge | Inspect element | 1 | 32900|
| yes | SQLi trainer | Simple union based SQL injection (from welcomectf 2024) | 1 | 32901|
| yes | Command injection | Command injection | 1 | 32902|
| yes | Local file inclusion | LFI | 1 | 32903|

### RE

| Done? | Name                       | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | -------------------------- | ------------------------------------------------------ | -------------------------- | ----------- |
| yes   | Artifact 10: Python        | Basic code reading (probably in Python)                | 1                          | -           |
| yes   | Artifact 11: Decompilation | Basic decompilation analysis                           | 1                          | -           |
| no    | Artifact 12: ???           | Basic disassembly analysis                             | 1.5                        | -           |
| yes   | Artifact 13: Functions     | Common functions / variables / type manipulation       | 2                          | -           |
| yes   | Artifact 14: Pointers      | Arrays / pointers / casting / dereferencing            | 3                          | -           |
| yes   | Artifact 15: Bitwise       | Number systems / bitwise exploration                   | 2                          | -           |

### Forensics

| Done? | Name              | Challenge Details                                                                                                         | Estimated Difficulty (1-5) | Port Number |
| ----- | ----------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------- |
| yes   | Lost my login creds     | VM forensics                  | 2                           | -            |

### README Templates

Essentially, all **README.md** files should contain the following information

| Things to include               | Example                                                                   |
| ------------------------------- | ------------------------------------------------------------------------- |
| Challenge Details               | `Caesar thought of the perfect cipher. Can you break it?`                 |
| Possible hints                  | `Hint: What Caesar Cipher?`                                               |
| Key concepts                    | `Scripting`                                                               |
| Solution (Can also be a script) | `Write a script to brute force all the combinations of the caesar cipher` |
| Learning objectives             | `Learn about the Caesar Cipher`                                           |
| Flag                            | `grey{salad_is_great_but_cipher_is_not}`                                  |

### Challenge folder format (challenges with services)
```
folder (your challenge name)
│   README.md
│   docker-compose.yml   
│
└───solve
│   │   (include all solution files here)
│
└───service
│   |   Dockerfile
│   |   (include all other files necessary for the service to run here e.g. .py files)
│      
└───distrib
    │   (include all files to be distributed to participants here)
```

### Challenge folder format (challenges without services)
```
folder (your challenge name)
│   README.md
│
└───solve
│   │   (include all solution files here)
│      
└───distrib
    │   (include all files to be distributed to participants here)
```





