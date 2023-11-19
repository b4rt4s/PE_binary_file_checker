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

#This function checks how many code and data sections a particular file contains.
#This is very important information when analyzing potential threats, because often malicious files contain many more code sections than data sections,
#or the distribution is simply disproportionate.
def count_code_data_sections(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        code_sections = data_sections = 0
        output_data = []

        for section in pe.sections:
            characteristics = section.Characteristics
            if characteristics & 0x20:
                code_sections += 1
            elif characteristics & 0x40:
                data_sections += 1

        output_data.append(f"Number of Code Sections: {code_sections}\n")
        output_data.append(f"Number of Data Sections: {data_sections}\n")

        if data_sections != 0:
            section_ratio = code_sections / data_sections
            output_data.append(f"Section Ratio (Code : Data): {section_ratio}\n")
        else:
            output_data.append("Section Ratio (Code : Data): N/A\n")

        with open(output_file, 'w') as file:
            file.writelines(output_data)

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")

#This function reads the resource section, which contains resources such as icons, texts, bitmaps and other resources used by programs.
#Using it, you can read their data and see if there are any unusual or suspicious resources in it
def analyze_resource_section(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                file.write(f"Resource Type: {resource_type.name}\n")
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]

                            file.write(f"\tResource ID: {resource_id.name}\n")
                            file.write(f"\tResource Language ID: {resource_lang.name}\n")
                            file.write(f"\tResource Size: {size}\n")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")

import pefile

#This function is to identify and check the digital signatures of the PE file.
#This can help you confirm the authenticity of this file and identify whether it has any unauthorized changes. 

def check_digital_signatures(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                file.write("Digital Signatures found in the file:\n")
                for entry in pe.DIRECTORY_ENTRY_SECURITY:
                    file.write(f"Signature: {entry.description}\n")
                    file.write(f"  Revision: {entry.revision}\n")
                    file.write(f"  Certificates:\n")
                    for cert in entry.certificates:
                        file.write(f"    Issuer: {cert.issuer}\n")
                        file.write(f"    Subject: {cert.subject}\n")

            else:
                file.write("No Digital Signatures found in the file.")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")

#Funkcja ta przegląda struktury danych w pliku PE takie jak tablice importu, eksportu, adresy relokacji itp.
#Pozwala to w łatwiejszy sposób zrozumieć jak zasoby są wykorzystywane przez plik co ułatwia poszukiwanie potencjalnych zagrożeń.
def analyze_pe_data_structures(file_path, output_file):
    try:
        pe = pefile.PE(file_path)

        with open(output_file, 'w') as file:
            file.write("PE Data Structures Analysis:\n")

            file.write("Imports:\n")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                file.write(f"  DLL: {entry.dll.decode()}\n")
                for imp in entry.imports:
                    file.write(f"    Function: {imp.name.decode()}\n")

            file.write("\nExports:\n")
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    file.write(f"  Exported Function: {exp.name.decode()}\n")

            file.write("\nBase Relocations:\n")
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for relocation in pe.DIRECTORY_ENTRY_BASERELOC.entries:
                    file.write(f"  Virtual Address: {hex(relocation.virtual_address)}\n")

    except pefile.PEFormatError as e:
        with open(output_file, 'w') as file:
            file.write(f"Error reading PE file: {e}")
