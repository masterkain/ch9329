# CH9329 Python Utility Toolkit

This repository contains a suite of Python scripts for configuring, testing, and troubleshooting the CH9329 UART to USB HID controller chip. These tools allow you to change the chip's USB identity (VID/PID, manufacturer strings), test its functionality, and prepare it for use in custom hardware projects.

The tools are designed to work with the CH9329's two primary modes of operation, which are physically selected via jumpers on the module.

## Understanding the CH9329 Operating Modes

This is the most critical concept. The mode you need depends on the task you want to perform.

### 1. Protocol Mode (for Configuration)

- **Jumper Setting:** All configuration jumpers (`CFG0`, `CFG1`) must be **OFF** (floating).
- **Purpose:** This is the default mode for changing the chip's internal settings. In this mode, the chip listens for special command packets over the serial port.
- **Tools to Use:** `ch9329_config_gui.py`, `ch9329_configurator.py`, `ch9329_baud_finder.py`.

### 2. Transparent Mode (for Operation)

- **Jumper Setting:** The jumpers must be physically set for Transparent Mode (`CFG1`=LOW, `CFG0`=HIGH).
- **Purpose:** This mode turns the chip into a simple, high-speed serial-to-HID bridge. It does not analyze data; it directly converts 8-byte serial packets into USB keyboard reports. This is the ideal mode for high-performance applications like a KVM or bot.
- **Tools to Use:** `ch9329_macos_solver.py`, `ch9329_transparent_tester.py`.

---

## Recommended Workflow for a New Device

For a new CH9329 chip, follow these steps in order:

1. **Configure (Protocol Mode):**

    - Set the jumpers to **PROTOCOL MODE (OFF)**.
    - Run `ch9329_config_gui.py` to set a custom VID/PID and device strings using the presets.
    - Power cycle the device.

2. **Prepare (Transparent Mode):**

    - Set the jumpers to **TRANSPARENT MODE (ON)**.
    - Power cycle the device.

3. **Solve for macOS (If Needed):**

    - If you are connecting the device to a Mac for the first time, run `ch9329_macos_solver.py` to complete the "Identify Your Keyboard" wizard.

4. **Test Functionality:**
    - Run `ch9329_transparent_tester.py` to send a series of keystrokes and verify that the device is working perfectly in its operational mode.

---

## The Utilities

### `ch9329_config_gui.py`

A user-friendly graphical tool to read and write the CH9329's internal settings.

- **Required Mode:** PROTOCOL MODE (Jumpers OFF)
- **Usage:**

  ```bash
  python ch9329_config_gui.py
  ```

- **Features:**
  - Automatically scans for available COM ports.
  - Load device identities from a list of presets (Logitech, Razer, etc.).
  - Read and write VID, PID, Manufacturer, Product, and Serial Number strings.
  - View the chip's stored default baud rate for Protocol Mode.
  - Advanced recovery tools: Software Reset and Factory Reset.
  - A live log panel provides detailed feedback on all operations.

### `ch9329_transparent_tester.py`

A comprehensive command-line script to verify that the chip is working correctly in Transparent Mode.

- **Required Mode:** TRANSPARENT MODE (Jumpers ON)
- **Usage:**

  ```bash
  # Auto-detects port, runs with default 115200 baud
  python ch9329_transparent_tester.py

  # Specify port and baud rate
  python ch9329_transparent_tester.py --port COM4 --baud 9600
  ```

- **Features:**
  - Sends a variety of single keys and complex hotkeys (e.g., `Shift+F5`, `Alt+Tab`).
  - Uses a local keyboard listener (`pynput`) to programmatically verify that the keystrokes are being correctly typed.
  - Provides a clear `SUCCESS` or `FAILURE` report for each test case.

### `ch9329_macos_solver.py`

An interactive command-line tool to complete the "Identify Your Keyboard" wizard on macOS.

- **Required Mode:** TRANSPARENT MODE (Jumpers ON)
- **Usage:**

  ```bash
  python ch9329_macos_solver.py --port <your_com_port>
  ```

- **Features:**
  - Provides a simple menu (`1` or `2`) corresponding to the prompts shown on the Mac screen.
  - Sends the specific keycodes (`Z` or `/`) that macOS uses to distinguish between ANSI and ISO keyboard layouts.

### `ch9329_configurator.py` (CLI Version)

A command-line interface for advanced users or scripting to perform all the same functions as the GUI.

- **Required Mode:** PROTOCOL MODE (Jumpers OFF)
- **Usage Examples:**

  ```bash
  # Read current configuration
  python ch9329_configurator.py --port COM3

  # Write a full configuration from a preset
  python ch9329_configurator.py --port COM3 --preset Razer_Huntsman

  # Write individual settings
  python ch9329_configurator.py --port COM3 --write --vid 046D --product "My Custom Keyboard"

  # Perform a factory reset
  python ch9329_configurator.py --port COM3 --do-factory-reset
  ```

### `ch9329_baud_finder.py` (Recovery Tool)

A diagnostic tool to find a chip's stored Protocol Mode baud rate if it was changed from the default and you've forgotten the new value.

- **Required Mode:** PROTOCOL MODE (Jumpers OFF)
- **Usage:**

  ```bash
  python ch9329_baud_finder.py --port <your_com_port>
  ```

- **Features:**
  - Systematically tests a list of common baud rates in an optimized order.
  - Sends a valid protocol handshake (`GET_CONFIG`) and programmatically verifies the response.
  - Stops immediately upon finding the correct baud rate.

---

## Prerequisites

These scripts require Python 3 and the `pyserial` and `pynput` libraries. You can install them with pip:

```bash
pip install pyserial pynput
```

or via uv:

```bash
uv sync
```
