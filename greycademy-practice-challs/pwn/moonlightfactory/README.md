# Challenge Name

Moonlight Factory

# Description

Do you know what a printf vulnerability is? I heard it can be used to leak secrets...

Here are some hints:

1. Full protections are enabled! Think PIE, ASLR, canary, etc...

2. Use printf vulnerability to leak canary and libc address

3. Use the docker container provided to ensure that printf behaves similarly to the remote server.

4. Since libc is not given to you, you need to extract it from the docker container and use it to replicate the remote environment. Libc binaries differ between different ubuntu versions.

# Summary

Use printf to leak libc then ret2libc

# Author

elijah5399

# Hints

nil

# Flag

`grey{I am a beacon of knowledge blazing out across a black sea of ignorance!!!}`
