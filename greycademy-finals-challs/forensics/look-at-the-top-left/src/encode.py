from PIL import Image
import sys

# Open image and convert to RGB
img = Image.open(sys.argv[1])
img = img.convert('RGB')
pixels = img.load()

# Convert text to bytes, then to bits
# text_bytes = "grey{err-gee-bee-fleg}".encode('utf-8')
text_bytes = b"grey{did-you-know-that-JPG-is-lossy-thats-why-the-flag-cant-be-in-the-LSB}"
bits = ''.join(format(byte, '08b') for byte in text_bytes)

bit_index = 0

for y in range(img.height):
    for x in range(img.width):
        if bit_index >= len(bits):
            break
        
        r, g, b = pixels[x, y]
        
        # Modify MSB of each channel
        if bit_index < len(bits):
            r = (r & 0x7F) | (int(bits[bit_index]) << 7)
            bit_index += 1
        if bit_index < len(bits):
            g = (g & 0x7F) | (int(bits[bit_index]) << 7)
            bit_index += 1
        if bit_index < len(bits):
            b = (b & 0x7F) | (int(bits[bit_index]) << 7)
            bit_index += 1
        
        pixels[x, y] = (r, g, b)
    
    if bit_index >= len(bits):
        break

# Save modified image
output = sys.argv[2] if len(sys.argv) > 2 else "modified.jpg"
img.save(output, quality=100, subsampling=0)
print(f"Saved to {output}")
