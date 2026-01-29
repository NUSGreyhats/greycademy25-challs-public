# Greycademy 2025 training challenges list

### pwn

| Done? | Name                  | Challenge Details                              | Estimated Difficulty (1-5) | Port Number |
| ----- | --------------------- | ---------------------------------------------- | -------------------------- | ----------- |
| yes   | handson-000           | learn scripting with pwntools                  | 1                          | 35000       |
| yes   | handson-001           | learn basic gdb skills                         | 2                          | 35001       |
| yes   | handson-002           | learn more gdb skills                          | 2                          | 35002       |
| yes   | handson-003           | learn ret2win                                  | 3                          | 35003       |
| yes   | handson-004           | learn ret2libc                                 | 4                          | 35004       |

### Web

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes   | sql injection           | part 1                  | 1                          | 30080        |
| yes   | cross-site scripting           | part 2                  | 1                          | 30080        |
| yes   | server side request forgery           | part 3                  | 1                          | 30080        |

### RE

| Done? | Name         | Challenge Details                                      | Estimated Difficulty (1-5) | Port Number |
| ----- | ------------ | ------------------------------------------------------ | -------------------------- | ----------- |
| yes   | artifact-1   | Introductory decompilation / disassembly analysis      | 1                          | -           |
| yes   | artifact-3   | Intermediate rev with some common decomp constructs    | 2                          | -           |
| yes   | artifact-4   | VM introduction / teaser                               | 3                          | -           |
| yes   | artifact-5   | Summative exercise                                     | 2.5                        | -           |

### Forensics

| Done? | Name              | Challenge Details                                                                                                         | Estimated Difficulty (1-5) | Port Number |
| ----- | ----------------- | ------------------------------------------------------------------------------------------------------------------------- | -------------------------- | ----------- |
| yes      | I Have Good Memory     | Memory forensics                  | 2                           | -            |
| yes |  Pcap 1 | Follow stream | 1 | - |
| yes | Pcap 2 | Pcap Export Objects | 1 | - |
| yes | Pcap 3 | DNS Exfiltration | 2 | - |
| yes | baby autopsy | use autopsy to analyse disk image | 2 | - |
| yes | Fix Me | fix magic bytes of PNG file | 1 | - |
| yes | Incomplete Meme | modify height metadata of JPG file | 1 | - |

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
