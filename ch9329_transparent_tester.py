# ch9329_transparent_tester.py

# CLI-driven script to test a CH9329 chip in Transparent Mode.

import argparse
import sys
import threading
import time

import serial
import serial.tools.list_ports
from pynput import keyboard

# --- Color Codes ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_END = "\033[0m"

# --- Global variables for the keyboard listener ---
captured_keys = set()
listener_active = True
capture_lock = threading.Lock()

HID_MAP = {
    "a": 0x04,
    "b": 0x05,
    "c": 0x06,
    "d": 0x07,
    "e": 0x08,
    "f": 0x09,
    "g": 0x0A,
    "h": 0x0B,
    "i": 0x0C,
    "j": 0x0D,
    "k": 0x0E,
    "l": 0x0F,
    "m": 0x10,
    "n": 0x11,
    "o": 0x12,
    "p": 0x13,
    "q": 0x14,
    "r": 0x15,
    "s": 0x16,
    "t": 0x17,
    "u": 0x18,
    "v": 0x19,
    "w": 0x1A,
    "x": 0x1B,
    "y": 0x1C,
    "z": 0x1D,
    "1": 0x1E,
    "2": 0x1F,
    "3": 0x20,
    "4": 0x21,
    "5": 0x22,
    "6": 0x23,
    "7": 0x24,
    "8": 0x25,
    "9": 0x26,
    "0": 0x27,
    "f1": 0x3A,
    "f2": 0x3B,
    "f3": 0x3C,
    "f4": 0x3D,
    "f5": 0x3E,
    "f6": 0x3F,
    "enter": 0x28,
    "esc": 0x29,
    "backspace": 0x2A,
    "tab": 0x2B,
    "space": 0x2C,
    # Modifiers
    "ctrl": 0xE0,
    "shift": 0xE1,
    "alt": 0xE2,
    "gui": 0xE3,  # Left
}


def _create_hid_report(hid_codes: list[int]) -> bytes:
    report = bytearray(8)
    modifier_byte = 0x00
    key_idx = 2
    for code in hid_codes:
        if 0xE0 <= code <= 0xE7:
            modifier_byte |= 1 << (code - 0xE0)
        elif key_idx < 8:
            report[key_idx] = code
            key_idx += 1
    report[0] = modifier_byte
    return bytes(report)


def send_key_press(serial_conn, key_names: list[str]):
    hid_codes = [HID_MAP[key] for key in key_names if key in HID_MAP]
    down_report = _create_hid_report(hid_codes)
    serial_conn.write(down_report)
    time.sleep(0.05)
    serial_conn.write(_create_hid_report([]))  # Release


def on_press(key):
    with capture_lock:
        key_name = None
        if isinstance(key, keyboard.KeyCode):
            key_name = key.char
        elif isinstance(key, keyboard.Key):
            key_name = key.name
        if key_name:
            captured_keys.add(key_name)


def start_keyboard_listener():
    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    print("OK. Keyboard listener is active in the background.")
    while listener_active:
        time.sleep(0.1)
    listener.stop()
    print("OK. Keyboard listener has been stopped.")


def run_tests(ser: serial.Serial):
    test_cases = [
        (["a"], {"a"}),
        (["shift", "a"], {"shift", "A"}),
        (["c"], {"c"}),
    ]

    passed_count = 0
    print(f"\n{C_BLUE}--- Running {len(test_cases)} Automated Tests ---{C_END}")
    time.sleep(2)

    for i, (keys_to_send, expected_capture) in enumerate(test_cases):
        print(f"--- Test {i+1}/{len(test_cases)} ---")
        print(f"--> Sending keys: {C_YELLOW}{keys_to_send}{C_END}")

        with capture_lock:
            captured_keys.clear()
        send_key_press(ser, keys_to_send)
        time.sleep(0.5)

        with capture_lock:
            print(f"<-- Captured keys: {C_YELLOW}{captured_keys}{C_END}")
            if expected_capture == captured_keys:
                print(f"    RESULT: {C_GREEN}SUCCESS{C_END}\n")
                passed_count += 1
            else:
                print(f"    EXPECTED: {C_YELLOW}{expected_capture}{C_END}")
                print(f"    RESULT: {C_RED}FAILURE{C_END}\n")
        time.sleep(1)

    print(f"\n--- Test Summary ---")
    print(f"    {passed_count} out of {len(test_cases)} tests passed.")
    print("--------------------")

    ## CHANGE: Added the rapid fire performance test.
    run_performance_test(ser)


def run_performance_test(ser: serial.Serial):
    print(f"\n{C_BLUE}--- Running Rapid-Fire Performance Test ---{C_END}")
    print("This test will send all alphabet keys as fast as possible.")
    print(f"{C_YELLOW}Please ensure you have a text editor (like Notepad) in focus!{C_END}")
    time.sleep(3)

    keys_to_fire = "abcdefghijklmnopqrstuvwxyz"
    total_keys = len(keys_to_fire)

    with capture_lock:
        captured_keys.clear()

    start_time = time.perf_counter()
    for char in keys_to_fire:
        # We send a very minimal key press here to maximize speed
        down_report = _create_hid_report([HID_MAP[char]])
        up_report = _create_hid_report([])
        ser.write(down_report)
        ser.write(up_report)
        # No artificial sleep, we want to go as fast as possible.
    end_time = time.perf_counter()

    # Wait a moment for all keys to register
    time.sleep(0.5)

    duration = end_time - start_time
    with capture_lock:
        keys_captured_count = len(captured_keys)

    kps = keys_captured_count / duration if duration > 0 else 0

    print("--- Performance Test Summary ---")
    print(f"    Sent {total_keys} keys in {duration:.3f} seconds.")
    print(f"    Captured {keys_captured_count} unique keys.")
    if keys_captured_count == total_keys:
        print(f"    {C_GREEN}All keys captured successfully!{C_END}")
    else:
        print(f"    {C_RED}MISSED {total_keys - keys_captured_count} KEYS! This indicates a potential bottleneck.{C_END}")
    print(f"    Achieved Rate: {C_YELLOW}{kps:.2f} Keys Per Second (KPS){C_END}")
    print("----------------------------------")


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

    print(f"\n{C_YELLOW}IMPORTANT: Ensure your CH9329 is in KEYBOARD-ONLY TRANSPARENT MODE.{C_END}")
    print(f"{C_YELLOW}Jumper on MODE0, Jumper on CFG1. All other jumpers OFF.{C_END}")
    input("Press Enter to begin the tests...")

    listener_thread = threading.Thread(target=start_keyboard_listener, daemon=True)
    listener_thread.start()
    time.sleep(1)

    try:
        with serial.Serial(com_port, args.baud, timeout=1) as ser:
            print(f"\n{C_GREEN}SUCCESS: Connected to {com_port} at {args.baud} baud.{C_END}")
            run_tests(ser)
    except serial.SerialException as e:
        print(f"\n{C_RED}FATAL ERROR: Could not open port '{com_port}'.{C_END}\nDetails: {e}")
    finally:
        global listener_active
        listener_active = False
        listener_thread.join()
        print("\nExiting program.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test a CH9329 in Transparent Mode.")
    parser.add_argument("--port", type=str, help="Specify the COM port (e.g., COM3). If omitted, the first available port is used.")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate for Transparent Mode (default: 115200).")
    parsed_args = parser.parse_args()
    main(parsed_args)
