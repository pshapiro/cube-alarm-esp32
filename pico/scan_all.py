# scan_any.py — robust BLE scanner without relying on specific IRQ constants
import bluetooth, time, machine

ble = bluetooth.BLE()
ble.active(True)

LED = machine.Pin("LED", machine.Pin.OUT)

def mac_str(addr_le):
    # addr is little-endian (memoryview/bytes) from IRQ, reverse to human order
    b = bytes(addr_le)
    return ":".join("{:02X}".format(x) for x in b[::-1])

def irq(event, data):
    # Some ports name events differently; we only care about "scan result"-shaped tuples:
    # (addr_type, addr, adv_type, rssi, adv_data)
    if isinstance(data, tuple) and len(data) == 5:
        addr_type, addr, adv_type, rssi, adv_data = data
        try:
            print("{:4d} dBm | {}".format(rssi, mac_str(addr)))
        except Exception as e:
            # Fallback if anything odd shows up
            print("scan evt", event, "len5, rssi", rssi, "addr(raw)", bytes(addr))
    else:
        # Uncomment to see other events’ codes while we diagnose
        # print("evt", event, "data len", len(data) if hasattr(data, "__len__") else "?")
        pass

ble.irq(irq)

print("Scanning 8 s… twist the cube to wake it.")
LED.on()
# Active scan (last arg True) often helps; if noisy, change to False
ble.gap_scan(8000, 30000, 30000, True)

# Keep script alive while scan runs
t0 = time.ticks_ms()
while time.ticks_diff(time.ticks_ms(), t0) < 8500:
    time.sleep_ms(50)
LED.off()
print("Scan done.")