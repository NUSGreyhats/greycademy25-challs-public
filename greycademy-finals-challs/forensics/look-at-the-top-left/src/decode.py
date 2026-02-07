from PIL import Image
import sys

# Open image and convert to RGB
img = Image.open(sys.argv[1])
img = img.convert('RGB')
pixels = list(img.getdata())

# Extract MSB from each RGB channel
bits = []
for pixel in pixels[:200]:  # 23 bytes * 8 bits = 184 bits / 3 channels = ~62 pixels
    r, g, b = pixel
    bits.append(str((r >> 7) & 1))
    bits.append(str((g >> 7) & 1))
    bits.append(str((b >> 7) & 1))

# Convert bits to bytes
bit_string = ''.join(bits)
text_bytes = []
for i in range(0, len(bit_string), 8):
    byte = bit_string[i:i+8]
    if len(byte) == 8:
        text_bytes.append(int(byte, 2))

# Convert bytes to text
flag = ''.join(chr(b) for b in text_bytes)
print(flag)  # First 23 characters (length of "grey{err-gee-bee-fleg}")
