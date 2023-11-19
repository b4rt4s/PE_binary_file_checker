file_path = "sample_files\\MinecraftInstaller.exe"
import basic_informations as basic_info
import security_informations as sec_info

def show_basic_informations_about_file(file_path):
    basic_info.read_pe_file_basic_info(file_path, "reports/basic_info_about_file.txt")
    basic_info.detect_imported_functions(file_path, "reports/imported_functions_info.txt")

def show_security_informations_about_file(file_path):
    sec_info.scan_all_sections(file_path, "reports/scan_all_sections.txt")
    sec_info.check_entry_point_address(file_path, "reports/check_if_entry_point_adress_correct.txt")

show_basic_informations_about_file(file_path)
show_security_informations_about_file(file_path)
