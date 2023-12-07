import pefile

def read_pe_components(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:

            # DOS Header
            file.write("DOS Header in HEX\n")
            for field in pe.DOS_HEADER.dump():
                file.write(f"{field}\n")
            file.write("\n")

            # PE Header
            file.write("PE Header in HEX\n")
            for field in pe.NT_HEADERS.FILE_HEADER.dump():
                file.write(f"{field}\n")
            file.write("\n")

            # Optional Header
            file.write("Optional Header in HEX\n")
            for field in pe.OPTIONAL_HEADER.dump():
                file.write(f"{field}\n")
            file.write("\n")

            # Data Directories
            file.write("Data Directories in HEX\n")
            for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                file.write(f"{directory}\n")
            file.write("\n")

            # Code (based on sections marked as executable)
            file.write("Code in HEX\n")
            for section in pe.sections:
                if section.Characteristics & 0x20:
                    section_name = section.Name.decode().rstrip('\x00')
                    file.write(f"Section: {section_name}\n")
                    file.write(f"{section.get_data().hex()}\n")
                    file.write("\n")

            # Imports
            file.write("Imports in HEX\n")
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    file.write(f"Import: {entry.dll.decode()}\n")
                    for imp in entry.imports:
                        file.write(f"{hex(imp.address)} - {imp.name.decode() if imp.name else ''}\n")
                file.write("\n")

            # Data (based on sections marked as containing initialized data)
            file.write("Data in HEX\n")
            for section in pe.sections:
                if section.Characteristics & 0x40:
                    section_name = section.Name.decode().rstrip('\x00')
                    file.write(f"Section: {section_name}\n")
                    file.write(f"{section.get_data().hex()}\n")
                    file.write("\n")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")


def read_pe_file_basic_info(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

            file.write("File Name: {}\n".format(file_path))
            file.write("Entry Point Address: {}\n".format(hex(entry_point) if hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint') else 'N/A'))
            file.write("File Size: {}\n".format(size_of_image if hasattr(pe.OPTIONAL_HEADER, 'SizeOfImage') else 'N/A'))

            # Read the PE signature as ASCII with zeros instead of unprintable characters
            signature = pe.NT_HEADERS.Signature if hasattr(pe.NT_HEADERS, 'Signature') else 0
            ascii_signature = ''.join(chr(byte) if 32 <= byte < 127 else '0' for byte in signature.to_bytes(4, byteorder='little'))
            file.write("File Signature (ASCII): {}\n".format(ascii_signature))

            file.write("\nSections:\n")
            for section in pe.sections:
                file.write("{} {} {}\n".format(section.Name.decode().strip('\x00'), section.SizeOfRawData, hex(section.VirtualAddress)))

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write("Error reading PE file: {}".format(e))
