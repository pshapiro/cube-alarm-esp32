# Cube Alarm ESP32

MicroPython firmware that turns a GAN Bluetooth cube into an alarm clock.

## Clock and alarm

- **Button A** (GP14) – hold to enter/exit time‑setting mode. While in this mode
  press **A** to increment hours and **B** to increment minutes.
- **Button B** (GP15) – hold to enter/exit alarm‑setting mode. While in alarm
  mode press **A** to increment hours and **B** to increment minutes.
- The cube is only polled shortly before the alarm (about 10 seconds) to avoid
  draining its battery.
- Stop the alarm by solving the cube or long‑pressing **B**.
- The OLED display shows the current time in a large 12‑hour format.

## REPL helpers

For quick testing you can schedule alarms from the REPL after running
`main.run()`:

```python
import main
main.set_alarm(7, 30)      # set an alarm at 07:30
main.set_alarm_in(30)      # alarm 30 seconds from now
```

