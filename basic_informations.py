import pefile 
import hashlib

def read_pe_file_basic_info(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

            file.write("File Name: {}\n".format(file_path))
            file.write("Entry Point Address: {}\n".format(hex(entry_point) if hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint') else 'N/A'))
            file.write("File Size: {}\n".format(size_of_image if hasattr(pe.OPTIONAL_HEADER, 'SizeOfImage') else 'N/A'))

            file.write("\nSections:\n")
            for section in pe.sections:
                file.write("{} {} {}\n".format(section.Name.decode().strip('\x00'), section.SizeOfRawData, hex(section.VirtualAddress)))

            with open(file_path, 'rb') as binary_file:
                file_content = binary_file.read()
                hash_md5 = hashlib.md5(file_content).hexdigest()
                file.write("\nMD5 Checksum: {}".format(hash_md5))

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write("Error reading PE file: {}".format(e))

def detect_imported_functions(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                file.write("DLL Library: {}\n".format(entry.dll.decode()))
                for imp in entry.imports:
                    file.write("\tImported Function: {}\n".format(imp.name.decode()))

    except Exception as e:
        with open(output_file, 'w') as file:
            file.write("Error while analyzing imported functions: {}".format(e))