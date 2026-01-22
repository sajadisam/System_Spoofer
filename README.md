# System Spoofer

## Description

System Spoofer is a C++ project designed to spoof various hardware and software identifiers on a Windows machine. It operates by modifying Windows Registry values to alter the reported information about the system's hardware and software, making it a useful tool for privacy and avoiding tracking by certain applications.

## Features

The System Spoofer can modify the following system identifiers:

- **Display Information**: Alters the reported information about connected displays.
- **GPU Information**: Modifies the Graphics Processing Unit (GPU) details.
- **Drive Information**: Changes the serial numbers and other identifiers of storage drives.
- **MAC Address**: Spoofs the Media Access Control (MAC) address of network adapters.
- **CPU Information**: Modifies the Central Processing Unit (CPU) details.
- **BIOS Information**: Alters the Basic Input/Output System (BIOS) information.
- **Windows Information**: Changes various Windows-related identifiers.

## How it Works

The core of the System Spoofer's functionality lies in its interaction with the Windows Registry. It targets specific registry keys where system hardware and software information is stored and overwrites the existing values with new, randomized, or user-defined data. The project includes a `RegistryManager` to handle the backup and restoration of the original registry values, ensuring that the changes can be reverted.

## Dependencies

- **Json**: The project uses the `nlohmann/json` library for handling JSON data, likely for configuration and data management.
- **Spdlog**: The `spdlog` library is used for logging, providing a flexible and efficient way to record the application's activity.

## Building

To build the project, you will need a C++ compiler that supports C++17 and CMake.

1. Create a build directory:
   ```bash
   cd System_Spoofer
   mkdir build && cd build
   ```
2. Run CMake and build the project:
   ```bash
   cmake ..
   make
   ```

## Usage

The main executable can be run to apply the spoofing. The application provides functions to spoof all identifiers at once or to target specific components.

**Important**: Running this application requires administrative privileges to modify the Windows Registry.

## Disclaimer

Modifying the Windows Registry can have unintended consequences and may cause system instability. This tool is provided for educational and research purposes only. The user is responsible for any damage caused by the use or misuse of this software. It is highly recommended to back up the registry before using this tool.
