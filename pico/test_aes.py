#!/usr/bin/env python3
"""
Simple AES test for MicroPython device
"""
import cryptolib

def _cbc(key, iv):
    return cryptolib.aes(key, 2, iv)

def decrypt_packet(pkt, key, iv):
    n = len(pkt)
    if n < 16:
        return None
    buf = bytearray(pkt)
    if n > 16:
        end_off = n - 16
        c = _cbc(key, iv)
        try:
            chunk = c.decrypt(bytes(buf[end_off:end_off+16]))
            buf[end_off:end_off+16] = chunk
        except Exception as e:
            print("! AES decrypt error (last chunk):", e)
            return pkt
    c = _cbc(key, iv)
    try:
        chunk = c.decrypt(bytes(buf[0:16]))
        buf[0:16] = chunk
    except Exception as e:
        print("! AES decrypt error (first chunk):", e)
        return pkt
    return bytes(buf)

# Test data from backend
key = bytes([157, 152, 12, 161, 219, 97, 22, 7, 32, 5, 24, 84, 66, 17, 18, 83])
iv = bytes([173, 153, 251, 161, 203, 208, 118, 39, 32, 149, 120, 20, 50, 18, 2, 67])
test_data = bytes([18, 52, 86, 120, 154, 188, 222, 240, 17, 34, 51, 68, 85, 102, 119, 136, 170, 187, 204, 221, 238, 255, 0, 17, 34, 51, 68, 85, 102, 119, 136, 153])

print("=== MicroPython AES Test ===")
print("Key len:", len(key))
print("IV len: ", len(iv))
print("Test data len:", len(test_data))

# Expected result from backend
expected = bytes([236, 40, 65, 189, 44, 43, 238, 8, 25, 9, 55, 127, 4, 86, 1, 236, 150, 79, 106, 234, 85, 157, 183, 95, 44, 43, 26, 77, 132, 103, 166, 105])

result = decrypt_packet(test_data, key, iv)
if result:
    print("SUCCESS: Decrypted", len(result), "bytes")
    if result == expected:
        print("MATCH: Decryption matches backend!")
    else:
        print("MISMATCH: Decryption differs from backend")
        print("Expected:", [hex(b) for b in expected[:8]], "...")
        print("Got:     ", [hex(b) for b in result[:8]], "...")
else:
    print("FAILED: Decryption returned None")

print("=== Test Complete ===")
