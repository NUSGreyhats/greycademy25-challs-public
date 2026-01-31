from  pwnlib.util.fiddling import xor

yes = bytes([10, 51, 11, 38, 12, 16, 127, 45, 62, 33, 111, 89, 29, 116, 49, 62, 37, 13, 16, 53, 52, 62, 43, 54, 25, 9, 93, 0, 21, 13, 8, 54, 15, 35, 54, 7, 10, 30, 6, 56, 29, 14, 36, 44, 5, 48])
key = b"mAn_whO_aM_i";
print(yes)
print( bytes([72, 101, 108, 108, 111]))
print(xor(key,yes))