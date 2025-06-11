# ch9329_configurator.py

# A professional command-line tool for configuring CH9329 chips.
# Features full protocol validation, presets, and recovery commands.
#
# MUST be used when the chip is in PROTOCOL MODE (jumpers OFF).

import argparse
import sys
import time

import serial
import serial.tools.list_ports

# --- Protocol Constants ---
HEAD = b"\x57\xab"
ADDR = b"\x00"
CMD_GET_CONFIG = b"\x08"
CMD_SET_CONFIG = b"\x09"
CMD_GET_USB_STRING = b"\x0a"
CMD_SET_USB_STRING = b"\x0b"
CMD_SET_DEFAULT_CFG = b"\x0c"
CMD_RESET = b"\x0f"

# --- Color Codes for Terminal Output ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_END = "\033[0m"

# --- Device Presets ---
PRESETS = {
    "Default": {"vid": "1A86", "pid": "E129", "manufacturer": "wch.cn", "product": "CH9329", "serial": ""},
    "Logitech_K120": {"vid": "046D", "pid": "C31C", "manufacturer": "Logitech", "product": "Keyboard K120", "serial": "2148LK120AABB"},
    "Razer_Huntsman": {"vid": "1532", "pid": "0226", "manufacturer": "Razer", "product": "Huntsman Elite", "serial": "PM2245R12345678"},
    "Corsair_K70R": {"vid": "1B1C", "pid": "1B09", "manufacturer": "Corsair", "product": "K70R keyboard", "serial": "78912345CORK70"},
    "Generic_Keyboard": {"vid": "04D9", "pid": "A06E", "manufacturer": "Generic", "product": "USB-HID Keyboard", "serial": ""},
}


### --- Core Communication and Validation Logic --- ###
def send_and_validate_command(ser: serial.Serial, cmd: bytes, data: bytes = b""):
    length = len(data).to_bytes(1, "little")
    packet_no_sum = HEAD + ADDR + cmd + length + data
    checksum = sum(packet_no_sum) & 0xFF
    final_packet = packet_no_sum + bytes([checksum])

    print(f"{C_BLUE}  TX -> Sending command {cmd.hex()}, packet: {final_packet.hex(' ')}{C_END}")
    ser.write(final_packet)
    time.sleep(0.1)
    response = ser.read_all()

    if not response:
        print(f"{C_RED}  RX <- FAILED! No response from device.{C_END}")
        return False, None
    print(f"{C_BLUE}  RX <- Received response: {response.hex(' ')}{C_END}")

    if not response.startswith(HEAD):
        print(f"{C_RED}  Validation FAILED: Invalid response header.{C_END}")
        return False, None

    response_checksum = response[-1]
    calculated_checksum = sum(response[:-1]) & 0xFF
    if response_checksum != calculated_checksum:
        print(f"{C_RED}  Validation FAILED: Checksum mismatch! (Got: {response_checksum:02X}, Expected: {calculated_checksum:02X}){C_END}")
        return False, None

    expected_resp_cmd = bytes([cmd[0] | 0x80])
    if response[3:4] != expected_resp_cmd:
        print(f"{C_RED}  Validation FAILED: Expected CMD {expected_resp_cmd.hex()}, got {response[3:4].hex()}{C_END}")
        return False, None

    print(f"{C_GREEN}  -> Command successful, response validated.{C_END}")
    return True, response[5:-1]  # Return just the payload


### --- High-Level API Functions --- ###
def read_full_config(ser: serial.Serial):
    print("\nAttempting to read full device configuration...")
    success, config_payload = send_and_validate_command(ser, CMD_GET_CONFIG)
    if not success or not config_payload or len(config_payload) < 50:
        return None

    config = {
        "vid": f"{int.from_bytes(config_payload[11:13], 'little'):04X}",
        "pid": f"{int.from_bytes(config_payload[13:15], 'little'):04X}",
        "default_baud": str(int.from_bytes(config_payload[3:7], "big")),
        "manufacturer": "",
        "product": "",
        "serial": "",
    }

    success_mfg, payload_mfg = send_and_validate_command(ser, CMD_GET_USB_STRING, b"\x00")
    if success_mfg and payload_mfg:
        config["manufacturer"] = payload_mfg[2 : 2 + payload_mfg[1]].decode("utf-8", errors="ignore")

    success_prod, payload_prod = send_and_validate_command(ser, CMD_GET_USB_STRING, b"\x01")
    if success_prod and payload_prod:
        config["product"] = payload_prod[2 : 2 + payload_prod[1]].decode("utf-8", errors="ignore")

    success_ser, payload_ser = send_and_validate_command(ser, CMD_GET_USB_STRING, b"\x02")
    if success_ser and payload_ser:
        config["serial"] = payload_ser[2 : 2 + payload_ser[1]].decode("utf-8", errors="ignore")

    return config


def write_full_config(ser: serial.Serial, new_settings: dict):
    print("\nAttempting to write new device configuration...")
    success, config_template = send_and_validate_command(ser, CMD_GET_CONFIG)
    if not success or not config_template:
        print(f"{C_RED}Could not read config template, aborting write.{C_END}")
        return

    new_config = bytearray(config_template)
    new_config[11:13] = int(new_settings["vid"], 16).to_bytes(2, "little")
    new_config[13:15] = int(new_settings["pid"], 16).to_bytes(2, "little")

    if any([new_settings["manufacturer"], new_settings["product"], new_settings["serial"]]):
        print(f"{C_BLUE}  -> Enabling custom USB strings flag.{C_END}")
        new_config[30] = 0x87

    success, _ = send_and_validate_command(ser, CMD_SET_CONFIG, bytes(new_config))
    if not success:
        print(f"{C_RED}Failed to write main configuration block!{C_END}")
        return

    print(f"{C_BLUE}  -> Writing string descriptors...{C_END}")
    s_mfg = new_settings["manufacturer"][:23]
    s_prod = new_settings["product"][:23]
    s_ser = new_settings["serial"][:23]
    send_and_validate_command(ser, CMD_SET_USB_STRING, bytes([0x00, len(s_mfg)]) + s_mfg.encode("utf-8"))
    send_and_validate_command(ser, CMD_SET_USB_STRING, bytes([0x01, len(s_prod)]) + s_prod.encode("utf-8"))
    send_and_validate_command(ser, CMD_SET_USB_STRING, bytes([0x02, len(s_ser)]) + s_ser.encode("utf-8"))

    print(f"\n{C_GREEN}Configuration written successfully!{C_END}")


def factory_reset(ser: serial.Serial):
    print(f"\n{C_YELLOW}Sending FACTORY RESET command...{C_END}")
    success, _ = send_and_validate_command(ser, CMD_SET_DEFAULT_CFG)
    if success:
        print(f"{C_GREEN}Factory reset command sent successfully.{C_END}")
    else:
        print(f"{C_RED}Failed to send factory reset command.{C_END}")


def software_reset(ser: serial.Serial):
    print(f"\n{C_YELLOW}Sending SOFTWARE RESET command...{C_END}")
    success, _ = send_and_validate_command(ser, CMD_RESET)
    if success:
        print(f"{C_GREEN}Software reset command sent successfully.{C_END}")
    else:
        print(f"{C_RED}Failed to send software reset command.{C_END}")


# --- Main Logic ---
def main(args):
    com_port = args.port
    if not com_port:
        ports = serial.tools.list_ports.comports()
        if not ports:
            print(f"\n{C_RED}FATAL ERROR: No serial ports found.{C_END}")
            sys.exit(1)
        com_port = ports[0].device
        print(f"No COM port specified, using first available: {C_YELLOW}{com_port}{C_END}")

    try:
        with serial.Serial(com_port, args.baud, timeout=0.2) as ser:
            print(f"\n{C_GREEN}SUCCESS! Connected to {com_port} at {args.baud} baud.{C_END}")

            if args.do_factory_reset:
                factory_reset(ser)
                return
            if args.do_reset:
                software_reset(ser)
                return

            settings_to_write = {}
            if args.preset:
                if args.preset not in PRESETS:
                    print(f"{C_RED}Error: Preset '{args.preset}' not found.{C_END}")
                    sys.exit(1)
                settings_to_write = PRESETS[args.preset].copy()
                print(f"\nLoaded preset '{C_YELLOW}{args.preset}{C_END}':")
                print(f"  VID={settings_to_write['vid']}, PID={settings_to_write['pid']}, Manufacturer={settings_to_write['manufacturer']}")

            # Allow command-line arguments to override presets
            if args.vid:
                settings_to_write["vid"] = args.vid
            if args.pid:
                settings_to_write["pid"] = args.pid
            if args.manufacturer:
                settings_to_write["manufacturer"] = args.manufacturer
            if args.product:
                settings_to_write["product"] = args.product
            if args.serial:
                settings_to_write["serial"] = args.serial

            if settings_to_write:
                write_full_config(ser, settings_to_write)
            else:
                print("\nNo write arguments provided. Performing read-only query...")
                current_config = read_full_config(ser)
                if current_config:
                    print("\n--- Current Device Settings ---")
                    for key, value in current_config.items():
                        print(f"  {key.replace('_', ' ').title()}: {value}")
                    print("-----------------------------")

    except serial.SerialException as e:
        print(f"\n{C_RED}FATAL ERROR: Could not open port '{com_port}'.{C_END}")
        print(f"Details: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("\n--- CH9329 USB Device Configurator (CLI) ---")
    print(f"\n{C_YELLOW}WARNING: Run this script with the CH9329 in PROTOCOL MODE (jumpers OFF).{C_END}")

    parser = argparse.ArgumentParser(description="Configure CH9329 USB parameters via command line.", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--port", type=str, help="Specify the COM port (e.g., COM3). If omitted, the first available port is used.")
    parser.add_argument("--baud", type=int, default=9600, help="The baud rate for the serial connection (default: 9600).")

    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument("--preset", choices=PRESETS.keys(), help="Write a full configuration from a defined preset.")
    action_group.add_argument("--write", action="store_true", help="Flag to enable writing of individual settings specified by --vid, --pid, etc.")
    action_group.add_argument("--do-factory-reset", action="store_true", help="Perform a factory reset on the chip.")
    action_group.add_argument("--do-reset", action="store_true", help="Perform a software reset on the chip.")

    parser.add_argument("--vid", type=str, help="Set Vendor ID (in hex, e.g., 1A86). Used with --preset or --write.")
    parser.add_argument("--pid", type=str, help="Set Product ID (in hex, e.g., E129). Used with --preset or --write.")
    parser.add_argument("--manufacturer", type=str, help="Set Manufacturer string. Used with --preset or --write.")
    parser.add_argument("--product", type=str, help="Set Product Name string. Used with --preset or --write.")
    parser.add_argument("--serial", type=str, help="Set Serial Number string. Used with --preset or --write.")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        print("\nExamples:")
        print("  Read current config: python ch9329_configurator.py --port COM3")
        print("  Write from preset:   python ch9329_configurator.py --port COM3 --preset Logitech_K120")
        print('  Write individual:    python ch9329_configurator.py --port COM3 --write --vid 046D --product "My Keyboard"')
        print("  Factory Reset:       python ch9329_configurator.py --port COM3 --do-factory-reset")
        sys.exit(0)

    parsed_args = parser.parse_args()

    # If only individual write args are given without the --write flag, show an error.
    if any([parsed_args.vid, parsed_args.pid, parsed_args.manufacturer, parsed_args.product, parsed_args.serial]) and not (parsed_args.write or parsed_args.preset):
        parser.error("To set individual values like --vid or --product, you must also include the --write flag.")

    main(parsed_args)

    print(f"\n{C_YELLOW}CRITICAL FINAL STEP: Power off the CH9329 and set jumpers BACK to TRANSPARENT MODE for normal use!{C_END}")
