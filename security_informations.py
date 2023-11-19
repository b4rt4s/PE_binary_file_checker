import pefile

#This function looks through all the sections in the PE file and identifies those that are code sections.
#It then checks their attributes, including whether the section is read-only (IMAGE_SCN_MEM_READ) or executable (IMAGE_SCN_MEM_EXECUTE).
#This helps identify potentially suspicious code sections that have unusual attributes.

def decode_section_name(section_name_bytes):
    try:
        return section_name_bytes.decode().rstrip('\x00')
    except UnicodeDecodeError:
        return ""

def scan_all_sections(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            for section in pe.sections:
                section_name = decode_section_name(section.Name)
                file.write(f"Section Name: {section_name}\n")
                file.write(f"Virtual Address: {hex(section.VirtualAddress)}\n")
                file.write(f"Raw Size: {section.SizeOfRawData}\n")
                file.write(f"Characteristics: {hex(section.Characteristics)}\n")
                file.write("\nChecking for Readable and Executable sections:\n")

                if section.Characteristics & 0x40000000:
                    file.write("Section is Readable\n")
                else:
                    file.write("Section is NOT Readable\n")

                if section.Characteristics & 0x20000000:
                    file.write("Section is Executable\n")
                else:
                    file.write("Section is NOT Executable\n")

                file.write("----------------------------------------\n")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")

#This function checks whether the entry point address falls within the valid range.
#The entry point address in a PE file is a virtual address from which the processor starts executing code.
#Verifying whether the address falls within the expected range is a crucial step in validating the integrity of an executable file.
def check_entry_point_address(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        size_of_image = pe.OPTIONAL_HEADER.SizeOfImage

        entry_point_address_lower = image_base
        entry_point_address_upper = image_base + size_of_image

        with open(output_file, 'w') as file:
            if entry_point_address_lower <= entry_point < entry_point_address_upper:
                file.write("Entry Point Address is within the valid range.")
            else:
                file.write("Entry Point Address is outside the valid range.")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write("Error reading PE file: {}".format(e))