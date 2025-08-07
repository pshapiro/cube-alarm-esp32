# Cube Alarm

This project turns a GAN Bluetooth cube into an alarm clock. When the alarm rings you must solve your cube to dismiss it!

## Backend (Python)

1. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```
2. Run the server
   ```bash
  python backend/alarm_server.py
  ```

### Custom alarm sound

The audio manager loads the alarm sound from the path stored in the
`ALARM_SOUND_FILE` environment variable.  If this variable is not set, it
defaults to `sounds/alarm.wav` relative to the project root.  Adjust this
variable to use a custom sound file.

## Frontend (React)

1. Install dependencies
   ```bash
   cd frontend
   npm install
   ```
2. Start the dev server
   ```bash
   npm start
   ```

## Getting your cube MAC address

The backend needs the real BLE MAC address of your cube. Run the BLE worker to scan and note the `Manufacturer MAC` it prints:
```bash
python backend/ble_worker.py
```
Set this address in a `.env` file or export `CUBE_MAC` before launching the server.

## Raspberry Pi Setup

### Flashing Raspberry Pi OS

Use the [Raspberry Pi Imager](https://www.raspberrypi.com/software/) to write
Raspberry Pi OS Lite to a microSD card. Boot the Pi, connect it to your network
then clone this repo and run `setup_pi.sh`.
The script installs the project in `~/cube-alarm` for the user that runs it,
so ensure you execute it as the user that should own the service.

### Bluetooth

Enable the Bluetooth service and pair your cube if needed:

```bash
sudo systemctl enable bluetooth
sudo systemctl start bluetooth
```

### Audio through the headphone jack

Route audio to the 3.5mm jack:

```bash
sudo raspi-config
```

Choose **Advanced Options → Audio → Headphones**.

### Setting volume

You can raise the default volume with PulseAudio:

```bash
pactl set-sink-volume 0 80%
```

### Running the server as a service

`setup_pi.sh` installs a systemd unit named `cube-alarm.service`.
Enable it at boot and start (or restart) it when needed:

```bash
sudo systemctl enable cube-alarm.service
sudo systemctl restart cube-alarm.service
```

Check logs with:

```bash
sudo journalctl -u cube-alarm -f
```

### Serving the React app with nginx

After building the frontend you can serve it with nginx:

```bash
cd frontend
npm install
npm run build
sudo cp -r build/* /var/www/html/
sudo systemctl enable nginx
sudo systemctl start nginx
```

## Hardware

You can purchase the GAN cube used for this project here: [GAN Smart Cube](https://amzn.to/4lgux9D).

## ESP32 Touchscreen Port

An initial MicroPython port targeting the **ESP32-2432S022C** board
with built‑in 2.2" capacitive touchscreen is available under the
[`esp32/`](esp32/) directory.  The port drives a MAX98357A I2S audio
amplifier for alarm playback and uses the ST7789 display controller. A
simple UI shows the current time, two editable alarms, and cube
connection/scramble status.

### Quick start

1. Flash [MicroPython](https://micropython.org/download/ESP32_GENERIC/)
   onto the board.
2. Copy `esp32/*.py` and `sounds/alarm.wav` to the device's filesystem.
3. Wire a MAX98357A module to the default I2S pins:

   | Signal | ESP32 Pin |
   | ------ | --------- |
   | `BCLK` | GPIO14    |
   | `LRC`  | GPIO15    |
   | `DIN`  | GPIO32    |

4. Reset the board – the home screen shows the current time, two alarm
   slots, and cube status. Tap the top area to set the time or the bottom
   corners to configure alarms. The alarm sound plays when a scheduled
   time is reached and stops on touch.

The MicroPython port is a work in progress; BLE integration with the
GAN cube and a full alarm scheduler are still to be implemented so cube
status is currently a placeholder.

## API Endpoints

The backend exposes a small set of HTTP routes for managing alarms and cube state.

- `GET /api/alarms` – retrieve all alarms
- `GET /api/alarms/active` – list alarms that are currently ringing
- `POST /api/alarms` – create a new alarm
- `PUT /api/alarms/<id>` – update an alarm
- `DELETE /api/alarms/<id>` – delete an alarm
- `POST /api/alarms/<id>/stop` – stop a specific alarm
- `POST /api/alarms/stop` – stop all alarms

## Credits

Huge thanks to [afedotov/gan-web-bluetooth](https://github.com/afedotov/gan-web-bluetooth) for the original logic used to communicate with the cube.

## License

This project is released under the custom license found in `LICENSE.txt`.
