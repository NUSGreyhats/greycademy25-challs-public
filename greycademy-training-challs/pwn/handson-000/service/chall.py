import time
import random

def main():
    start = time.time()
    for i in range(10):
        a = random.randint(10000, 10000000)
        b = random.randint(10000, 10000000)
        operator = random.choice(["+", "-", "*"])
        expr = f"{a} {operator} {b}"
        c = eval(expr)


        print(f"{i+1} / 10")

        attempt = input(f"{expr} = ")

        end = time.time()
        duration = end - start
        print(f"Time elapsed: {round(duration)} seconds")

        if duration > 5:
            print("Took too long!")

        try:
            attempt = int(attempt)
        except ValueError:
            print("Invalid input!")
            exit(-1)

        if attempt != c:
            print("Wrong answer!")
            exit(-1)
    else:
        print("flag{m4th_g3niu5}")

if __name__ == "__main__":
    main()
