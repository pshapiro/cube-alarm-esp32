# scan_mac.py — safe MAC printer for MicroPython
import bluetooth, time

ble = bluetooth.BLE()
ble.active(True)

def mac_str(addr_le):
    # addr_le is a buffer-like object (memoryview)
    b = bytes(addr_le)
    # reverse manually (MicroPython-safe)
    return ":".join("{:02X}".format(b[i]) for i in range(len(b) - 1, -1, -1))

def irq(event, data):
    if isinstance(data, tuple) and len(data) == 5:
        addr_type, addr, adv_type, rssi, adv_data = data
        try:
            print("{:4d} dBm | {}".format(rssi, mac_str(addr)))
        except Exception as e:
            print("Bad addr:", addr, e)

ble.irq(irq)

print("Scanning 10 s… twist the cube to wake it.")
ble.gap_scan(10000, 30000, 30000, True)

time.sleep(11)
print("Scan done.")
