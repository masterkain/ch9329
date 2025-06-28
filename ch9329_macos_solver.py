# ch9329_macos_solver.py

# CLI-driven tool to solve the macOS Keyboard Setup Assistant.

import argparse
import sys
import time

import serial
import serial.tools.list_ports

# --- Color Codes for Terminal Output ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_END = "\033[0m"

# --- USB HID Keycode Map ---
HID_MAP = {
    "z": 0x1D,  # Key to the RIGHT of LEFT SHIFT
    "/": 0x38,  # Key to the LEFT of RIGHT SHIFT
}


def send_keystroke(serial_connection, char_to_send: str):
    """Builds and sends a raw 8-byte HID report for a single key press."""
    keycode = HID_MAP[char_to_send]

    packet_press = bytes([0x00, 0x00, keycode, 0x00, 0x00, 0x00, 0x00, 0x00])
    packet_release = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    print(f"\nSending press for the '{char_to_send}' key (HID Code: {hex(keycode)})...")
    serial_connection.write(packet_press)
    time.sleep(0.05)
    serial_connection.write(packet_release)
    print("Keystroke sent successfully.")


# --- Main Program ---
def main(args):
    com_port = args.port
    if not com_port:
        print("No COM port specified, scanning for available ports...")
        ports = serial.tools.list_ports.comports()
        if not ports:
            print(f"\n{C_RED}FATAL ERROR: No serial ports found.{C_END}")
            sys.exit(1)
        com_port = ports[0].device
        print(f"  -> Found port: {C_YELLOW}{com_port}{C_END}. Using this one.")

    print("\n--- macOS Keyboard Assistant Solver ---")

    try:
        with serial.Serial(com_port, args.baud, timeout=1) as ser:
            print(f"\n{C_GREEN}SUCCESS! Connected to {com_port} at {args.baud} baud.{C_END}")
            print("Ready for your commands. Look at the Mac screen for prompts.")
            print("-" * 55)

            while True:
                print("\nWhich key is the macOS Assistant asking you to press?")
                print("  (1) The key to the RIGHT of the LEFT SHIFT key.")
                print("  (2) The key to the LEFT of the RIGHT SHIFT key.")

                user_input = input("\nEnter your choice (1 or 2), or type 'quit' to exit: ").lower().strip()

                if user_input == "quit":
                    break

                if user_input == "1":
                    send_keystroke(ser, "z")
                elif user_input == "2":
                    send_keystroke(ser, "/")
                else:
                    print(f"\n{C_RED}Invalid input: '{user_input}'. Please enter only '1', '2', or 'quit'.{C_END}")
                    continue

                print("\nCheck the Mac screen. If it asks for another key, repeat the step.")
                print("If the wizard closes, you are done!")

    except serial.SerialException as e:
        print(f"\n{C_RED}FATAL ERROR: Could not open port '{com_port}'.{C_END}")
        print(f"Details: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Solve the macOS Keyboard Assistant via CH9329.")
    parser.add_argument("--port", type=str, help="Specify the COM port (e.g., COM3). If omitted, the first available port is used.")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate for Transparent Mode (default: 115200).")
    parsed_args = parser.parse_args()
    main(parsed_args)
    print("\nExiting program.")
