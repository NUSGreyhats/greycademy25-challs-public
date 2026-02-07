flag = b"grey{Six_SeVen_SIx_sEVeN_six_SEVen_siX_SEVeN_sIx_SeVeN_SiX_sEVen!!}"

state = 76
def lcg():
    global state
    state = (state * 67 + 86)
    return state

expected = []
s = set()
for i in range(len(flag)):
    idx = pow(13, i+1, 67)
    s.add(idx)
    print(idx)
    expected.append((flag[idx] ^ lcg()) & 0xff)
for i in range(1, 67):
    assert i in s, f"Missing index {i}"

print(bytes(expected))