# ch9329_baud_finder.py

# A diagnostic tool to find the stored protocol baud rate of a CH9329 chip.
# This version uses an optimized test order for faster discovery.
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

# --- Color Codes for Terminal Output ---
C_GREEN = "\033[92m"
C_RED = "\033[91m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_END = "\033[0m"

# We test the most likely candidates first: the highest common speed,
# then the factory default, then the rest in descending order.
BAUD_RATES_TO_TEST = [115200, 9600, 57600, 38400, 19200, 4800, 2400, 1200]


def test_baud_rate(port: str, rate: int) -> bool:
    """
    Opens the COM port at a specific rate, sends a "get config" command,
    and checks for a valid, protocol-compliant response.
    """
    print(f"\n--- TESTING BAUD RATE: {C_YELLOW}{rate}{C_END} ---")
    try:
        with serial.Serial(port, rate, timeout=0.3) as ser:
            print(f"  Port opened successfully. Sending handshake command...")

            # Build and send a simple "get config" command packet
            length = b"\x00"
            packet_no_sum = HEAD + ADDR + CMD_GET_CONFIG + length
            checksum = sum(packet_no_sum) & 0xFF
            final_packet = packet_no_sum + bytes([checksum])

            ser.write(final_packet)
            response = ser.read(64)

            if not response:
                print(f"  {C_RED}Result: No response. Incorrect baud rate.{C_END}")
                return False

            print(f"  {C_BLUE}Result: Got a response! Validating...{C_END}")
            # Check if the response is valid (header and correct response command)
            if response.startswith(HEAD) and response[3:4] == bytes([CMD_GET_CONFIG[0] | 0x80]):
                print(f"  {C_GREEN}VALIDATION SUCCESS! Correct baud rate found.{C_END}")
                return True
            else:
                print(f"  {C_RED}Result: Response was invalid. Incorrect baud rate.{C_END}")
                return False

    except serial.SerialException:
        print(f"  {C_RED}Could not open port at {rate}. It might be in use. Skipping.{C_END}")
        return False


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

    print(f"\n{C_YELLOW}IMPORTANT: Ensure your CH9329 is in PROTOCOL MODE (jumpers OFF).{C_END}")
    input("Press Enter to begin the test cycle...")

    found_rate = None
    for baud in BAUD_RATES_TO_TEST:
        if test_baud_rate(com_port, baud):
            found_rate = baud
            break
        time.sleep(1)

    print("\n" + "=" * 50)
    if found_rate:
        print(f"{C_GREEN}      Test cycle complete. Baud rate found!      {C_END}")
        print(f"\n    The chip's stored protocol baud rate is: {C_YELLOW}{found_rate}{C_END}")
        print("    Use this rate when connecting with the configuration GUI.")
    else:
        print(f"{C_RED}      Test cycle complete. No valid rate found.      {C_END}")
        print("\n    Please check your wiring and ensure the chip is powered on.")
    print("=" * 50)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find the protocol baud rate of a CH9329 chip.")
    parser.add_argument("--port", type=str, help="Specify the COM port (e.g., COM3). If omitted, the first available port is used.")
    parsed_args = parser.parse_args()
    main(parsed_args)
