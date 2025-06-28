# ch9329_configurator_gui.py

# A user-friendly and protocol-compliant GUI for configuring CH9329 chips.
#
# MUST be used when the chip is in PROTOCOL MODE (jumpers OFF).

import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import serial
import serial.tools.list_ports

# --- Protocol Constants ---
HEAD = b"\x57\xab"
ADDR = b"\x00"
CMD_GET_CONFIG = b"\x08"
CMD_SET_CONFIG = b"\x09"
CMD_SET_USB_STRING = b"\x0b"
CMD_GET_USB_STRING = b"\x0a"
CMD_SET_DEFAULT_CFG = b"\x0c"
CMD_RESET = b"\x0f"


class ConfigApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CH9329 Device Configurator")
        self.geometry("540x720")

        self.serial_connection = None
        self.log_lock = threading.Lock()

        self.presets = {
            "Select a Preset...": {},
            "Default CH340": {"vid": "1A86", "pid": "E129", "manufacturer": "wch.cn", "product": "CH9329", "serial": ""},
            "Logitech K120": {"vid": "046D", "pid": "C31C", "manufacturer": "Logitech", "product": "Keyboard K120", "serial": "2148LK120AABB"},
            "Razer Huntsman": {"vid": "1532", "pid": "0226", "manufacturer": "Razer", "product": "Huntsman Elite", "serial": "PM2245R12345678"},
            "Corsair K70R": {"vid": "1B1C", "pid": "1B09", "manufacturer": "Corsair", "product": "K70R keyboard", "serial": "78912345CORK70"},
        }

        self.port_var = tk.StringVar()
        self.baud_var = tk.IntVar(value=9600)
        self.status_var = tk.StringVar(value="Status: Disconnected")
        self.vid_var = tk.StringVar()
        self.pid_var = tk.StringVar()
        self.manufacturer_var = tk.StringVar()
        self.product_var = tk.StringVar()
        self.serial_var = tk.StringVar()
        self.preset_var = tk.StringVar(value="Select a Preset...")
        self.stored_baud_var = tk.StringVar(value="(read from device)")

        self._create_widgets()
        self._scan_ports()

        self._update_widget_state(connected=False)

    def _log(self, message: str, level: str = "INFO"):
        with self.log_lock:
            timestamp = time.strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] [{level}] {message}\n"
            self.after(0, self._update_log_text, formatted_message)

    def _update_log_text(self, message):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")

    def _set_ui_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.read_btn.config(state=state)
        self.write_btn.config(state=state)
        self.reset_btn.config(state=state)
        self.factory_reset_btn.config(state=state)
        self.connect_btn.config(state=state)
        self.port_combo.config(state=state)
        self.baud_combo.config(state=state)

    def _update_widget_state(self, connected):
        config_state = "normal" if connected else "disabled"
        connect_btn_text = "Disconnect" if connected else "Connect"

        # Set state for action buttons
        self.read_btn.config(state=config_state)
        self.write_btn.config(state=config_state)
        self.reset_btn.config(state=config_state)
        self.factory_reset_btn.config(state=config_state)

        # Set state for the connection button itself
        self.connect_btn.config(text=connect_btn_text)

        # Set state for the editable configuration widgets inside the frame
        self.vid_entry.config(state=config_state)
        self.pid_entry.config(state=config_state)
        self.manufacturer_entry.config(state=config_state)
        self.product_entry.config(state=config_state)
        self.serial_entry.config(state=config_state)
        self.stored_baud_combo.config(state=config_state)

    def _toggle_connection(self):
        if self.serial_connection and self.serial_connection.is_open:
            self.serial_connection.close()
            self.serial_connection = None
            self.status_var.set("Status: Disconnected")
            self._update_widget_state(connected=False)
            self.stored_baud_var.set("(read from device)")
            self._log("Disconnected from port.", "SYSTEM")
        else:
            port, baud = self.port_var.get(), self.baud_var.get()
            if not port:
                messagebox.showerror("Error", "No COM port selected.")
                return
            try:
                self._log(f"Attempting to connect to {port} at {baud} baud...", "SYSTEM")
                self.serial_connection = serial.Serial(port, baud, timeout=0.2)
                self.status_var.set(f"Status: Connected to {port}")
                self._update_widget_state(connected=True)
                self._log("Connection successful.", "SUCCESS")
                self._read_config_threaded()
            except serial.SerialException as e:
                messagebox.showerror("Connection Failed", str(e))
                self.status_var.set("Status: Connection Failed")
                self._log(f"Connection failed: {e}", "ERROR")

    def _read_config_threaded(self):
        self._set_ui_busy(True)
        threading.Thread(target=self._read_config, daemon=True).start()

    def _write_config_threaded(self):
        if messagebox.askyesno("Confirm Write", "This will permanently change the chip's settings. Are you sure?"):
            self._set_ui_busy(True)
            threading.Thread(target=self._write_config, daemon=True).start()

    def _reset_device_threaded(self):
        if messagebox.askyesno("Confirm Reset", "This will perform a software reset on the device (like unplugging it). Continue?"):
            self._set_ui_busy(True)
            threading.Thread(target=self._reset_device, daemon=True).start()

    def _factory_reset_threaded(self):
        if messagebox.askyesno("Confirm Factory Reset", "This will restore the chip to its original factory settings, wiping all changes. THIS IS PERMANENT. Are you sure?"):
            self._set_ui_busy(True)
            threading.Thread(target=self._factory_reset, daemon=True).start()

    def _send_and_validate_command(self, cmd: bytes, data: bytes = b""):
        if not self.serial_connection or not self.serial_connection.is_open:
            self._log(f"Command {cmd.hex()} cancelled, port not open.", "WARN")
            return False, None

        length = len(data).to_bytes(1, "little")
        packet_no_sum = HEAD + ADDR + cmd + length + data
        checksum = sum(packet_no_sum) & 0xFF
        final_packet = packet_no_sum + bytes([checksum])
        self._log(f"Sending command {cmd.hex()}, packet: {final_packet.hex(' ')}", "TX")

        try:
            self.serial_connection.write(final_packet)
            if cmd in (CMD_SET_CONFIG, CMD_SET_USB_STRING, CMD_SET_DEFAULT_CFG):
                time.sleep(0.5)
            else:
                time.sleep(0.1)
            response = self.serial_connection.read_all()
        except (serial.SerialException, AttributeError) as e:
            self.status_var.set(f"Status: Serial Error")
            self._log(f"Serial Error during send/read: {e}", "ERROR")
            return False, None

        if not response:
            self._log("No response from device.", "ERROR")
            return False, None

        self._log(f"Received response: {response.hex(' ')}", "RX")
        if not response.startswith(HEAD):
            self.status_var.set("Status: Error - Invalid response")
            self._log("Response header is invalid.", "ERROR")
            return False, None

        if len(response) < 5:
            self.status_var.set("Status: Error - Runt packet")
            self._log(f"Response packet is too short: {len(response)} bytes.", "ERROR")
            return False, None

        response_checksum = response[-1]
        packet_to_check = response[:-1]
        calculated_checksum = sum(packet_to_check) & 0xFF
        if response_checksum != calculated_checksum:
            self.status_var.set("Status: Error - Checksum mismatch!")
            self._log("Checksum validation failed!", "ERROR")
            return False, None

        expected_resp_cmd = bytes([cmd[0] | 0x80])
        if response[3:4] != expected_resp_cmd:
            self.status_var.set("Status: Error - Wrong response CMD")
            self._log(f"Expected CMD {expected_resp_cmd.hex()}, got {response[3:4].hex()}", "ERROR")
            return False, None

        payload = response[5:-1]
        self._log("Command successful, response validated.", "SUCCESS")
        return True, payload

    def _read_config(self):
        try:
            self._log("Reading configuration...")
            success, config_payload = self._send_and_validate_command(CMD_GET_CONFIG)
            if not success or config_payload is None or len(config_payload) < 50:
                self.status_var.set("Status: Failed to read config")
                self._log("Reading config block failed.", "ERROR")
                return

            self.vid_var.set(f"{int.from_bytes(config_payload[11:13], 'little'):04X}")
            self.pid_var.set(f"{int.from_bytes(config_payload[13:15], 'little'):04X}")
            self.stored_baud_var.set(str(int.from_bytes(config_payload[3:7], "big")))

            self.manufacturer_var.set(self._get_usb_string(0))
            self.product_var.set(self._get_usb_string(1))
            self.serial_var.set(self._get_usb_string(2))

            self.status_var.set(f"Status: Config read from {self.port_var.get()}")
            self._log("All device parameters read and populated.", "SUCCESS")
        finally:
            self.after(100, lambda: self._set_ui_busy(False))

    def _get_usb_string(self, descriptor_type: int) -> str:
        self._log(f"Reading USB string (Type: {descriptor_type})...")
        success, payload = self._send_and_validate_command(CMD_GET_USB_STRING, bytes([descriptor_type]))
        if success and payload:
            try:
                length = payload[1]
                value = payload[2 : 2 + length].decode("utf-8", errors="ignore")
                self._log(f"  -> Got string: '{value}'")
                return value
            except IndexError:
                self._log(f"  -> Failed to parse string payload.", "ERROR")
                return "N/A (Malformed)"
        self._log(f"  -> Failed to get string.", "ERROR")
        return "N/A"

    def _write_config(self):
        try:
            self._log("Starting write process...")
            try:
                vid, pid = int(self.vid_var.get(), 16), int(self.pid_var.get(), 16)
                new_baud = int(self.stored_baud_var.get())
            except ValueError:
                messagebox.showerror("Input Error", "VID/PID must be valid hex and Baud Rate must be a valid number.")
                self._log("Invalid hex value for VID/PID or non-integer baud rate.", "ERROR")
                return

            success, config_payload = self._send_and_validate_command(CMD_GET_CONFIG)
            if not success or not config_payload:
                self._log("Cannot write: failed to get template config.", "ERROR")
                return

            new_config = bytearray(config_payload)
            new_config[3:7] = new_baud.to_bytes(4, "big")

            new_config[11:13] = vid.to_bytes(2, "little")
            new_config[13:15] = pid.to_bytes(2, "little")
            if any([self.manufacturer_var.get(), self.product_var.get(), self.serial_var.get()]):
                self._log("Enabling custom USB strings flag.")
                new_config[30] = 0x87

            success, _ = self._send_and_validate_command(CMD_SET_CONFIG, bytes(new_config))
            if not success:
                messagebox.showerror("Error", "Failed to write main config block.")
                self._log("Writing main config block failed.", "ERROR")
                return

            self._set_usb_string(0, self.manufacturer_var.get())
            self._set_usb_string(1, self.product_var.get())
            self._set_usb_string(2, self.serial_var.get())

            self._log("All configuration written successfully.", "SUCCESS")
            messagebox.showinfo("Success", "Configuration written successfully!\n\nPlease power-cycle the device and use the new baud rate to connect if you changed it.")
            self.status_var.set("Status: Write complete. Re-read to verify.")
        finally:
            self.after(100, lambda: self._set_ui_busy(False))

    def _set_usb_string(self, descriptor_type: int, new_string: str):
        if len(new_string) > 23:
            new_string = new_string[:23]
        self._log(f"Writing USB string (Type: {descriptor_type}): '{new_string}'...")
        data_payload = bytes([descriptor_type, len(new_string)]) + new_string.encode("utf-8")
        self._send_and_validate_command(CMD_SET_USB_STRING, data_payload)

    def _reset_device(self):
        try:
            self._log("Sending software reset command...", "WARN")
            success, _ = self._send_and_validate_command(CMD_RESET)
            if success:
                messagebox.showinfo("Success", "Device reset command sent.")
                self.after(100, self._toggle_connection)
            else:
                messagebox.showerror("Error", "Failed to send reset command.")
        finally:
            self.after(100, lambda: self._set_ui_busy(False))

    def _factory_reset(self):
        try:
            self._log("Sending FACTORY RESET command...", "CRITICAL")
            success, _ = self._send_and_validate_command(CMD_SET_DEFAULT_CFG)
            if success:
                messagebox.showinfo("Success", "Factory reset sent.\nPower-cycle device and re-read.")
            else:
                messagebox.showerror("Error", "Failed to send factory reset command.")
        finally:
            self.after(100, lambda: self._set_ui_busy(False))

    def on_closing(self):
        if self.serial_connection and self.serial_connection.is_open:
            self.serial_connection.close()
        self.destroy()

    def _scan_ports(self):
        ports = [port.device for port in serial.tools.list_ports.comports()]
        self.port_combo["values"] = ports
        if ports:
            self.port_var.set(ports[0])

    def _apply_preset(self, event=None):
        preset_name = self.preset_var.get()
        if preset_name in self.presets:
            data = self.presets[preset_name]
            self.vid_var.set(data.get("vid", ""))
            self.pid_var.set(data.get("pid", ""))
            self.manufacturer_var.set(data.get("manufacturer", ""))
            self.product_var.set(data.get("product", ""))
            self.serial_var.set(data.get("serial", ""))

    def _create_widgets(self):
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill="both", expand=True)
        conn_frame = ttk.LabelFrame(main_frame, text="1. Connection", padding="10")
        conn_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(conn_frame, text="COM Port:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.port_combo = ttk.Combobox(conn_frame, textvariable=self.port_var, state="readonly", width=15)
        self.port_combo.grid(row=0, column=1, sticky="ew", padx=5)
        ttk.Button(conn_frame, text="Refresh", command=self._scan_ports).grid(row=0, column=2, padx=5)
        ttk.Label(conn_frame, text="Baud Rate:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        baud_values = ["9600", "19200", "38400", "57600", "115200"]
        self.baud_combo = ttk.Combobox(conn_frame, textvariable=self.baud_var, values=baud_values, width=15)
        self.baud_combo.grid(row=1, column=1, sticky="ew", padx=5)
        self.connect_btn = ttk.Button(conn_frame, text="Connect", command=self._toggle_connection)
        self.connect_btn.grid(row=0, column=3, rowspan=2, padx=10, ipady=10)
        status_label = ttk.Label(conn_frame, textvariable=self.status_var, relief="sunken", anchor="center")
        status_label.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        conn_frame.columnconfigure(1, weight=1)
        instr_frame = ttk.LabelFrame(main_frame, text="IMPORTANT: Jumper Settings", padding="10")
        instr_frame.pack(fill="x", pady=5)
        ttk.Label(instr_frame, text="• For this tool: Use PROTOCOL MODE (Jumpers OFF).\n• For bot: Use TRANSPARENT MODE (CFG1=LOW, CFG0=HIGH).", foreground="red").pack()
        self.config_frame = ttk.LabelFrame(main_frame, text="2. Device Identity", padding="10")
        self.config_frame.pack(fill="x", pady=5)
        ttk.Label(self.config_frame, text="Load Preset:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.preset_combo = ttk.Combobox(self.config_frame, textvariable=self.preset_var, values=list(self.presets.keys()), state="readonly")
        self.preset_combo.grid(row=0, column=1, columnspan=3, sticky="ew", padx=5, pady=5)
        self.preset_combo.bind("<<ComboboxSelected>>", self._apply_preset)

        ttk.Label(self.config_frame, text="VID (Hex):").grid(row=1, column=0, sticky="w", padx=5, pady=2)
        self.vid_entry = ttk.Entry(self.config_frame, textvariable=self.vid_var)
        self.vid_entry.grid(row=1, column=1, sticky="ew")

        ttk.Label(self.config_frame, text="PID (Hex):").grid(row=1, column=2, sticky="w", padx=5, pady=2)
        self.pid_entry = ttk.Entry(self.config_frame, textvariable=self.pid_var)
        self.pid_entry.grid(row=1, column=3, sticky="ew")

        ttk.Label(self.config_frame, text="Manufacturer:").grid(row=2, column=0, sticky="w", padx=5, pady=2)
        self.manufacturer_entry = ttk.Entry(self.config_frame, textvariable=self.manufacturer_var)
        self.manufacturer_entry.grid(row=2, column=1, columnspan=3, sticky="ew")

        ttk.Label(self.config_frame, text="Product Name:").grid(row=3, column=0, sticky="w", padx=5, pady=2)
        self.product_entry = ttk.Entry(self.config_frame, textvariable=self.product_var)
        self.product_entry.grid(row=3, column=1, columnspan=3, sticky="ew")

        ttk.Label(self.config_frame, text="Serial Number:").grid(row=4, column=0, sticky="w", padx=5, pady=2)
        self.serial_entry = ttk.Entry(self.config_frame, textvariable=self.serial_var)
        self.serial_entry.grid(row=4, column=1, columnspan=3, sticky="ew")

        ttk.Label(self.config_frame, text="Stored Baud:").grid(row=5, column=0, sticky="w", padx=5, pady=2)
        self.stored_baud_combo = ttk.Combobox(self.config_frame, textvariable=self.stored_baud_var, values=baud_values)
        self.stored_baud_combo.grid(row=5, column=1, columnspan=3, sticky="ew", padx=5)

        self.config_frame.columnconfigure(1, weight=1)
        self.config_frame.columnconfigure(3, weight=1)
        action_frame = ttk.Frame(main_frame, padding=(0, 5))
        action_frame.pack(fill="x")
        self.read_btn = ttk.Button(action_frame, text="Read from Device", command=self._read_config_threaded)
        self.read_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.write_btn = ttk.Button(action_frame, text="Write to Device", command=self._write_config_threaded)
        self.write_btn.pack(side="left", expand=True, fill="x", padx=2)
        danger_frame = ttk.LabelFrame(main_frame, text="3. Advanced/Recovery", padding="10")
        danger_frame.pack(fill="x", pady=5)
        self.reset_btn = ttk.Button(danger_frame, text="Software Reset", command=self._reset_device_threaded)
        self.reset_btn.pack(side="left", expand=True, fill="x", padx=2)
        self.factory_reset_btn = ttk.Button(danger_frame, text="Factory Reset", command=self._factory_reset_threaded)
        self.factory_reset_btn.pack(side="left", expand=True, fill="x", padx=2)
        log_frame = ttk.LabelFrame(main_frame, text="4. Live Log", padding="10")
        log_frame.pack(fill="both", expand=True, pady=(5, 0))
        self.log_text = tk.Text(log_frame, height=8, wrap="word", state="disabled", bg="#f0f0f0")
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)


if __name__ == "__main__":
    app = ConfigApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
