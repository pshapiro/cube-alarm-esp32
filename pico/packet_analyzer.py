#!/usr/bin/env python3
"""
Comprehensive packet analyzer for solved cube state detection
"""

def analyze_packet_structure(packet_hex: str):
    """Analyze packet structure to find valid cube data."""
    packet = bytes.fromhex(packet_hex.replace(' ', '').replace(':', ''))
    bits = ''.join(f'{b:08b}' for b in packet)
    
    print(f"Packet: {packet.hex().upper()}")
    print(f"Length: {len(packet)} bytes = {len(bits)} bits")
    print(f"Bits: {bits}")
    print()
    
    # Try to find ANY valid edge permutation pattern
    valid_patterns = []
    
    for start_bit in range(0, len(bits) - 44, 1):  # Need 44 bits for 11*4-bit values
        ep_values = []
        valid = True
        
        for i in range(11):
            bit_pos = start_bit + i * 4
            if bit_pos + 4 > len(bits):
                valid = False
                break
            val = int(bits[bit_pos:bit_pos+4], 2)
            ep_values.append(val)
        
        if valid and len(ep_values) == 11:
            ep_sum = sum(ep_values)
            final_ep = 66 - ep_sum
            
            # Check if this could be a valid edge permutation
            if all(0 <= v <= 11 for v in ep_values) and 0 <= final_ep <= 11:
                # Check if it's a valid permutation (each number 0-11 appears once)
                all_ep = ep_values + [final_ep]
                if len(set(all_ep)) == 12 and set(all_ep) == set(range(12)):
                    valid_patterns.append({
                        'start_bit': start_bit,
                        'ep': all_ep,
                        'is_identity': all_ep == list(range(12))
                    })
    
    if valid_patterns:
        print("✅ Found valid edge permutation patterns:")
        for pattern in valid_patterns:
            print(f"   Bit {pattern['start_bit']}: EP = {pattern['ep']}")
            if pattern['is_identity']:
                print(f"      🎯 IDENTITY PERMUTATION (SOLVED!)")
        return valid_patterns
    else:
        print("❌ No valid edge permutation patterns found")
        
        # Show closest attempts
        print("\nClosest attempts (valid 4-bit values):")
        for start_bit in range(0, min(80, len(bits) - 44), 4):
            ep_values = []
            for i in range(11):
                bit_pos = start_bit + i * 4
                if bit_pos + 4 <= len(bits):
                    val = int(bits[bit_pos:bit_pos+4], 2)
                    ep_values.append(val)
            
            if len(ep_values) == 11 and all(0 <= v <= 15 for v in ep_values):
                ep_sum = sum(ep_values)
                final_ep = 66 - ep_sum
                valid_range = all(0 <= v <= 11 for v in ep_values)
                print(f"   Bit {start_bit}: {ep_values} + [{final_ep}] "
                      f"(valid_range: {valid_range})")
        
        return []

def create_test_solved_packet():
    """Create a test packet with identity permutation to verify parsing."""
    # Identity permutation: CP=[0,1,2,3,4,5,6,7], EP=[0,1,2,3,4,5,6,7,8,9,10,11]
    # CO=[0,0,0,0,0,0,0,0], EO=[0,0,0,0,0,0,0,0,0,0,0,0]
    
    # Pack the data manually
    bits = ['0'] * 152  # 19 bytes = 152 bits
    
    # Pack corners at bit 0 (test position)
    bit_pos = 0
    for i in range(7):  # First 7 corners
        cp_val = i  # Identity: 0,1,2,3,4,5,6
        for j in range(3):  # 3 bits per corner
            if cp_val & (1 << (2-j)):
                bits[bit_pos] = '1'
            bit_pos += 1
    
    # Final corner will be 7 (28 - 0-1-2-3-4-5-6 = 7)
    
    # Pack corner orientations (all 0)
    for i in range(8):  # 8 corners, 2 bits each
        bit_pos += 2  # All zeros, already initialized
    
    # Pack edges at next available position
    for i in range(11):  # First 11 edges  
        ep_val = i  # Identity: 0,1,2,3,4,5,6,7,8,9,10
        for j in range(4):  # 4 bits per edge
            if ep_val & (1 << (3-j)):
                bits[bit_pos] = '1'
            bit_pos += 1
    
    # Final edge will be 11 (66 - 0-1-2-3-4-5-6-7-8-9-10 = 11)
    
    # Pack edge orientations (all 0)
    for i in range(12):  # 12 edges, 1 bit each
        bit_pos += 1  # All zeros, already initialized
    
    # Convert back to bytes
    bit_string = ''.join(bits)
    packet = bytearray()
    for i in range(0, len(bit_string), 8):
        byte_bits = bit_string[i:i+8].ljust(8, '0')
        packet.append(int(byte_bits, 2))
    
    return bytes(packet)

# Test with sample packets
if __name__ == "__main__":
    print("=== Analyzing Captured Packet ===")
    captured = "C6A63D79D250ADC612EF9C492E2951273AE2F9"
    analyze_packet_structure(captured)
    
    print("\n=== Creating Test Solved Packet ===")
    test_packet = create_test_solved_packet()
    print(f"Test packet: {test_packet.hex().upper()}")
    analyze_packet_structure(test_packet.hex())

print("Run this on device to capture fresh solved packet:")
print("# Press A button when cube is definitely solved")
print("# Look for CLR 19 : lines in output")
