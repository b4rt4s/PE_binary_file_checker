file_path = "sample_files\\MinecraftInstaller.exe"
import basic_informations as basic_info
import security_informations as sec_info

def show_basic_informations_about_file(file_path):
    basic_info.read_pe_components(file_path, "reports/read_pe_components.txt")
    basic_info.read_pe_file_basic_info(file_path, "reports/read_pe_file_basic_info.txt")

def show_security_informations_about_file(file_path):
    sec_info.scan_all_sections(file_path, "reports/scan_all_sections.txt")
    sec_info.check_entry_point_address(file_path, "reports/check_entry_point_address.txt")
    sec_info.count_code_data_sections(file_path, "reports/count_code_data_sections.txt")
    sec_info.analyze_resource_section(file_path, "reports/analyze_resource_section.txt")
    sec_info.check_digital_signatures(file_path, "reports/check_digital_signatures.txt")
    sec_info.analyze_debug_sections(file_path, "reports/analyze_debug_sections.txt")
    sec_info.analyze_dependency_sections(file_path, "reports/analyze_dependency_sections.txt")
    sec_info.analyze_import_export_sections(file_path, "reports/analyze_import_export_sections.txt")
    sec_info.warnings_pe_file_basic_info(file_path, "reports/warnings_pe_file_basic_inf.txt")

show_basic_informations_about_file(file_path)
show_security_informations_about_file(file_path)
