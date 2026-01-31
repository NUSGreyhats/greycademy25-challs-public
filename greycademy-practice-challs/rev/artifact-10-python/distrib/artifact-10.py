print('Welcome to the first practice challenge!')
print('Reverse engineering is really a big part really just reading all kinds of code.')
print('So hopefully you know how Python works...')
print('(If not, you can perhaps consult a short Python tutorial online ;))')

###########
# STAGE 1 #
###########

def stage_1(x):
    if x - 50 < 4787566 - 50:
        return 0
    if x + 100 > 4787566 + 100:
        return 0
    x += 1234567890 # i am going to confuse you with these!
    x *= 1234567890 # mwahahahahahahahahahahahahahahahaha!!
    return 1
morning = int(input('Enter the first number: >>> '))
if not stage_1(morning):
    print('You do not know the secret code. :(')
    print('Goodbye!')
    exit()

print('Wow, that\'s pretty impressive...')

###########
# STAGE 2 #
###########

def stage_2(x):
    a = x - 17
    b = a / 128
    c = b - 67
    d = c / 107
    e = d - 46
    f = e / 85
    g = f - 39
    h = g / 53
    i = h - 49
    if i == 61:
        return 1
    return 0
afternoon = int(input('Enter the first number: >>> '))
if not stage_2(afternoon):
    print('You do not know the secret code. :(')
    print('Goodbye!')
    exit()

print('You got past this stage!?')
print('But hopefully you know why your teachers hate non-descriptive variable names...')

###########
# STAGE 3 #
###########

FUNNY_ARRAY = [58, 12, 5, 62, 30]
def stage_3(x):
    a = x * 67
    b = a % 5     # hopefully you know what modulo (%) does!
                  # it just takes the remainder of a division.
                  # search online if unsure!
    c = FUNNY_ARRAY[b]
    d = a + c
    if d == 497972353:
        return 1
    return 0
evening = int(input('Enter the third number: >>> '))
if not stage_3(evening):
    print('You do not know the secret code. :(')
    print('Goodbye!')
    exit()

print('I have been defeated... You won.')
print('Turns out, the real flag was the friends we made along the way...')

flag = 'grey{' + str(morning) + '_' + str(afternoon) + '_' + str(evening) + '}'
print(flag)
