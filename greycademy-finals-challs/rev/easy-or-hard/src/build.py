import os
os.system("musl-gcc -static -O2 -s ./encrypt_file.c ./chacha20_broken.c -I . -o ./build/encrypt_file")

out = os.popen("./build/encrypt_file").read()
length, data = out.split("\n")[:2]
main = open("./main.c", "r").read()

main = main.replace("PL_LEN 0", f"PL_LEN {length}")
main = main.replace("char buf[PL_LEN] = {};", data)

open("./build/main_out.c", "w").write(main)
os.system("musl-gcc -static -O2 -s ./build/main_out.c ./chacha20_broken.c -I . -o ./build/easy_or_hard")