# Greycademy 2025 finals challenge list

### Welcome

| Done? | Name | Challenge Details | Estimated Difficulty (1-5) | Port Number |
| ----- | ---- | ----------------- | -------------------------- | ----------- |
|       |      |                   |                            |             |

### pwn

| Done? | Name                  | Challenge Details                              | Estimated Difficulty (1-5) | Port Number |
| ----- | --------------------- | ---------------------------------------------- | -------------------------- | ----------- |
| yes | scrabble | leak libc and skip past canary to ret2libc | 4 | 30000 |
| yes | abyss | overwrite buffer index ptr then ret2win | 2 | 30001 |
| yes | void | ROP with strict seccomp rule, no canary no PIE static | 3 | 30002 |
| yes | backdoor | overwrite function pointer, no PIE | 1 | 30003 |
| yes | vending machine | bypass scanf double using ., leak libc, re-run binary and ret2libc | 5 | 30004

### Web

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes | My Name ___ | window.name XSS | 3 | 31001 and 31002 |
| yes | 6 Or 7 | Zip file extract path traversal -> command injection | 4 | 31003 |
| yes | Portal| SQLi -> DNS-Rebinding | 4 | 31004 |
| yes | Summary Judgement | Blind time-based prompt injection | 3 | 31005 |
| yes | curled | Baby web, follow the instructions | 1-2? | 31006 |

### RE

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes |  license  | flag checker again | 2 ||
| yes | stack-vm revenge | stack vm | 4 ||
| yes | 67 | Register based VM using LCG + XOR encryption | 5 ||
| yes | meoware | malware analysis with rc4, not stripped | 3 ||
| yes | easy or hard | Flag sent in HTTP request | 1 ||

### Forensics

| Done? | Name              | Challenge Details                                                                                                         | Estimated Difficulty (1-5) | Port Number |
| ----- | ----------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------- |
| yes | finals presentation | Replaced slide layout xml | 1 ||
| yes | hide and seek | Memdump with process hollowing | 3/4 |32000|
| yes | look at the top left | MSB stego in JPG file (cannot be solved by zsteg) | 2/3 ||
| yes | locked temporary storage | flag in user's AppData\Temp, drive is bitlocker encrypted but with recovery key in AD (NTDS provided)  | 5 ||

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
