import argparse
import csv
import tkinter as tk
from datetime import datetime
from tkinter import filedialog
from urllib.parse import urlparse
from url_patter import *
from apk_decoder import *
from ASConfig import ASConfig
from logger import as_logger, ASLogger
from statis import *


CONFIG_NAME = 'config.ini'


def select_file():
    root = tk.Tk()
    root.withdraw()
    file_type = (('All files', '*.*'), ('Android Packets', '*.apk'), ('Android Packet Bundles', '*.xapk'))
    file_path = filedialog.askopenfilename(title='Please select files', filetypes=file_type)
    return file_path, os.path.basename(file_path)


def select_directory():
    root = tk.Tk()
    root.withdraw()
    directory = filedialog.askdirectory()
    root.destroy()
    return directory


def delete_files_in_folder(folder_path):
    if not os.path.exists(folder_path):
        as_logger.info("Delete files: File not exist.")
        return
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
                as_logger.debug(f"Deleted {file_path}")
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
                as_logger.debug(f"Deleted {file_path}")
        except Exception as e:
            as_logger.error(f"Failed to delete {file_path}. Reason: {e}")


def extract_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def sanitize_filename(filename):
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


# Write to result_path + result_class + file_name
def result_to_csv(result_list, result_path, result_class, file_name):
    file_name = sanitize_filename(file_name)
    result_dir = os.path.join(result_path, result_class)
    path = os.path.join(result_dir, file_name)
    os.makedirs(result_dir, exist_ok=True)
    with open(path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=result_list[0].keys())
        writer.writeheader()
        for row in result_list:
            writer.writerow(row)


def add_record(file_path, obj):
    file_exists = os.path.isfile(file_path)
    with open(file_path, mode='a+', newline='', encoding='utf-8') as file:
        fieldnames = ['apk_path', 'apk_name', 'status', 'cause', 'detect_time', 'time_spent']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(obj)


def process_all(as_config, apk_path, apk_name):
    as_config.reload(CONFIG_NAME)
    ASLogger().setup_logger(as_config)
    file_name, file_extension = os.path.splitext(apk_name)
    if file_extension.lower() not in as_config.accept_apk_extensions:
        as_logger.warning(f"The selected file is not an acceptable file, "
                          f"please select such as {as_config.accept_apk_extensions} file.")
        return {"apk_path": apk_path, "apk_name": apk_name, "status": "failed", "cause": "Extension wrong"}
    delete_files_in_folder(as_config.decode_apk_path)
    delete_files_in_folder(as_config.store_apk_path)
    apks_path = [apk_path]
    if file_extension == ".xapk":
        as_logger.info(f"Detect xapk at \"{apk_path}\"! ")
        apks_path = decode_xapk(apk_path, as_config.store_apk_path, as_config.decode_apk_path)
        if len(apks_path) != 0:
            as_logger.info(f"Decoding \"{apk_path}\"  successfully! ")
        else:
            as_logger.warning(f"Decode \"{apk_path}\"  failed cause Xapk doesn't contain anything.")
            return {"apk_path": apk_path, "apk_name": apk_name, "status": "failed",
                    "cause": "Xapk doesn't contain anything "}
    domain_list = []
    for apk_path_item in apks_path:
        print(f"Start decode apk: \"{apk_path_item}\"! ")
        try:
            if decode_apk(apk_path_item, as_config.decode_apk_path):
                as_logger.info(f"Decoding \"{apk_path_item}\" successfully! ")
                files_list = scan_folder_for_urls(as_config.decode_apk_path, as_config.skip_dirs,
                                                  as_config.scan_extensions)
                domain_to_files = {}
                for file, urls in files_list.items():
                    for url in urls:
                        domain = extract_domain(url)
                        if domain not in domain_to_files:
                            domain_to_files[domain] = {"urls": [], "files": []}
                        domain_to_files[domain]["urls"].append(url)
                        domain_to_files[domain]["files"].append(file)
                domain_list = domain_list + [
                    {"domain": domain, "url": item["urls"], "files_path": item["files"]}
                    for domain, item in domain_to_files.items()
                ]
            else:
                as_logger.warning(f"Decode failed.")
                continue
        except Exception as e:
            as_logger.critical(f"Encounter an exception that {e}")
            continue
    timestamp = datetime.now()
    formatted_date = timestamp.strftime("%Y%m%d%H%M%S")
    result_name = as_config.domain_file_name.replace("%(timestamp)%", formatted_date)\
        .replace("%(apkname)%", apk_name).replace("%(filename)%", file_name)
    if len(domain_list) != 0:
        as_logger.info(f"Writing result to \"{result_name}\"...")
        result_to_csv(domain_list, as_config.result_path, "", result_name)
        as_logger.info(f"Writing \"{result_name}\" successfully!")
    else:
        as_logger.warning(f"There are no domain names included in this APK: \"{apk_path}\".")
        return {"apk_path": apk_path, "apk_name": apk_name, "status": "failed", "cause": "No domain"}
    # has_ipv6_domain_list = []
    # non_existent_domain_list = []
    # for item in domain_list:
    #     print(f"Finding \"{item['domain']}\" IPv6 address...")
    #     aaaa_records = get_aaaa_records(item["domain"], as_config.nameservers)
    #     if aaaa_records:
    #         record_list = []
    #         for rec in aaaa_records:
    #             record_list.append(rec)
    #         item["record"] = record_list
    #         has_ipv6_domain_list.append(item)
    #     else:
    #         print("No AAAA records found.")
    #         non_existent_domain_list.append(item)
    # result_to_csv(has_ipv6_domain_list, as_config.result_path, apk_name, as_config.has_ipv6_file_name)
    # result_to_csv(non_existent_domain_list, as_config.result_path, apk_name, as_config.non_existent_file_name)
    return {"apk_path": apk_path, "apk_name": apk_name, "status": "success", "cause": "None"}

def order_result(as_config):
    as_logger.info("Executing order_result operation...")
    domains_file_name = os.path.join(as_config.statistics_path, as_config.order_file_name)
    merge_and_deduplicate_domains(as_config.result_path, domains_file_name)
    

def statistics_apk(as_config):
    as_logger.info("Executing statistics_apk operation...")
    statistics_apk_file_name = os.path.join(as_config.statistics_path, as_config.statistics_apk_file_name)
    list_apk_files(as_config.library_path, statistics_apk_file_name, as_config.accept_apk_extensions)

def analyse(as_config):
    as_logger.info("Executing analyse operation...")
    # apk_path, apk_name = select_file()
    # if apk_path == "":
    #     exit(-1)
    # process_all(as_config, apk_path, apk_name)
    record_file_name = os.path.join(as_config.statistics_path, as_config.index_list_file_name)
    # selected_directory = select_directory()
    selected_directory = as_config.library_path
    as_logger.info(f"Selected directory: {selected_directory}")
    if selected_directory == "":
        exit(-1)
    apk_list = []
    for root, dirs, files in os.walk(selected_directory):
        for file in files:
            _, file_extension = os.path.splitext(file)
            if file_extension.lower() in as_config.accept_apk_extensions:
                apk_path = os.path.join(root, file)
                apk_list.append({"filename": file, "full_path": apk_path})
    as_logger.info(f"Found {len(apk_list)} {as_config.accept_apk_extensions}")
    if len(apk_list) != 0:
        for apk_item in apk_list:
            start_time = datetime.now() 
            result = process_all(as_config, apk_item["full_path"], apk_item["filename"])
            end_time = datetime.now()
            # if result["status"] != "success":
            result["time_spent"] = (end_time - start_time).total_seconds()
            result["detect_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            add_record(record_file_name, result)
    else:
        as_logger.warning(f"No {as_config.accept_apk_extensions} found!")
    as_logger.info(f"All APKs have been decoded and scanned, and the decoding completion time {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

def main():
    as_config = ASConfig(CONFIG_NAME)
    ASLogger().setup_logger(as_config)
    as_logger.info("Set logger successfully !")
    as_config.display()
    as_logger.info(f"Using nameserver: {as_config.nameservers}")
    parser = argparse.ArgumentParser(description="Process some operations based on the provided arguments.")
    parser.add_argument('--order-result', action='store_true', help='Execute the order_result operation.')
    parser.add_argument('--statistics-apk', action='store_true', help='Execute the statistics_apk operation.')
    parser.add_argument('--analyse', action='store_true', help='Execute the analyse operation.')
    args = parser.parse_args()
    if args.order_result:
        order_result(as_config)
    elif args.statistics_apk:
        statistics_apk(as_config)
    else:
        analyse(as_config)

if __name__ == '__main__':
    main()
