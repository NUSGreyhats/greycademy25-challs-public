# Greycademy 2025 qualifiers challenge list

### Welcome

| Done? | Name | Challenge Details | Estimated Difficulty (1-5) | Port Number |
| ----- | ---- | ----------------- | -------------------------- | ----------- |
|       |      |                   |                            |             |

### pwn

| Done? | Name                  | Challenge Details                              | Estimated Difficulty (1-5) | Port Number |
| ----- | --------------------- | ---------------------------------------------- | -------------------------- | ----------- |
| yes | babyrop | ROP with PIE leak and gadgets within the program | 4 | 30000 |
| yes | genie | OOB Write + Integer underflow | 2 | 30001 |
| yes | coffee_shop | printf vulnerability to leak string | 3 | 30002 |
| yes | easypwn | leak canary and ret2win | 1 | 30003 |
| yes | milk tea shop | stack pivot into bss then one gadget | 5 | 30004 |

### Web

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes | insecure file storage | File traversal using double url encoding | 2 | 31000 |
| yes | pack battle | XSS via flask templates | 1 | 31001|
| yes |  sourceless web | inspecting html, css, js | 1 | 31002 |
| yes |  matcha shop | path traversal + SSRF | 3 | 31003 |
| yes | greycademy directory | SQL injection | 1 | 31004 |

### RE

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes |  flag checker part 999  | simple xor loop | 1 ||
| yes | stack-vm | stack vm | 3 ||
| yes | fast-fingers | TUI game that is unsolvable without cheating | 2 ||
| yes | fake-blockchain | flagchecker but using linked-list | 4 || 

### Forensics

| Done? | Name              | Challenge Details                                                                                                         | Estimated Difficulty (1-5) | Port Number |
| ----- | ----------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------- |
| yes | ping pong | extract icmp data | 1 | - |
| yes | thin | FAT12 deleted file with modified header | 1 | - |
| yes | sus | memdump containing a crackme | 3 | - |
| yes | replaying flags | decrypt TLS traffic in wireshark | 4 | - |

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
