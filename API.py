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


def _delete_files_in_folder(folder_path):
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


def _extract_domain(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc


def _sanitize_filename(filename):
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def to_csv(result_list, result_dir, file_name):
    file_name = _sanitize_filename(file_name)
    path = os.path.join(result_dir, file_name)
    os.makedirs(result_dir, exist_ok=True)
    with open(path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=result_list[0].keys())
        writer.writeheader()
        for row in result_list:
            writer.writerow(row)


def _add_record(file_path, obj):
    file_exists = os.path.isfile(file_path)
    with open(file_path, mode='a+', newline='', encoding='utf-8') as file:
        fieldnames = ['apk_path', 'apk_name', 'status', 'cause', 'detect_time', 'time_spent']
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(obj)


def _process_all(as_config, apk_path, apk_name):
    ASLogger().setup_logger(as_config)
    file_name, file_extension = os.path.splitext(apk_name)
    if file_extension.lower() not in as_config.accept_apk_extensions:
        as_logger.warning(f"The selected file is not an acceptable file, "
                          f"please select such as {as_config.accept_apk_extensions} file.")
        return {"apk_path": apk_path, "apk_name": apk_name, "status": "failed", "cause": "Extension wrong"}
    _delete_files_in_folder(as_config.decode_apk_path)
    _delete_files_in_folder(as_config.store_apk_path)
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
                        domain = _extract_domain(url)
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
        return ({"apk_path": apk_path, "apk_name": apk_name, "status": "success", "cause": "None"}, domain_list)
    else:
        as_logger.warning(f"There are no domain names included in this APK: \"{apk_path}\".")
        return ({"apk_path": apk_path, "apk_name": apk_name, "status": "failed", "cause": "No domain"}, [])

def _order_result(data):
    as_logger.info("Executing order result operation...")
    all_domains = data
    merged_data = pd.DataFrame(all_domains)
    as_logger.info(f'去重前的域名总数: {len(merged_data)}')
    unique_domains = merged_data.drop_duplicates(subset='domain')
    as_logger.info(f'合并后去重的域名总数: {len(unique_domains)}')
    return unique_domains
    

def _statistics_apk(as_config):
    as_logger.info("Executing _statistics_apk operation...")
    _statistics_apk_file_name = os.path.join(as_config.statistics_path, as_config._statistics_apk_file_name)
    list_apk_files(as_config.library_path, _statistics_apk_file_name, as_config.accept_apk_extensions)


def _analyse(as_config):
    as_logger.info("Executing _analyse operation...")
    # apk_path, apk_name = select_file()
    # if apk_path == "":
    #     exit(-1)
    # _process_all(as_config, apk_path, apk_name)
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
            result = _process_all(as_config, apk_item["full_path"], apk_item["filename"])
            end_time = datetime.now()
            # if result["status"] != "success":
            result["time_spent"] = (end_time - start_time).total_seconds()
            result["detect_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            _add_record(record_file_name, result)
    else:
        as_logger.warning(f"No {as_config.accept_apk_extensions} found!")
    as_logger.info(f"All APKs have been decoded and scanned, and the decoding completion time {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    
async def parse_single_file(apk_path, apk_file_name):
    as_config = ASConfig(CONFIG_NAME)
    ASLogger().setup_logger(as_config)
    as_logger.info("Set logger successfully !")
    as_config.display()
    as_logger.info(f"Using nameserver: {as_config.nameservers}")
    as_logger.info("Executing analyse operation...")
    record_file_name = os.path.join(as_config.statistics_path, as_config.index_list_file_name)
    start_time = datetime.now() 
    record, result = _process_all(as_config, os.path.join(apk_path, apk_file_name), apk_file_name)
    end_time = datetime.now()
    record["time_spent"] = (end_time - start_time).total_seconds()
    record["detect_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
    _add_record(record_file_name, record)
    as_logger.info(f"All APKs have been decoded and scanned, and the decoding completion time {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return result
    
    
def parse_mult_file(apk_path):
    as_config = ASConfig(CONFIG_NAME)
    ASLogger().setup_logger(as_config)
    as_logger.info("Set logger successfully !")
    as_config.display()
    as_logger.info(f"Using nameserver: {as_config.nameservers}")
    as_logger.info("Executing analyse operation...")
    record_file_name = os.path.join(as_config.statistics_path, as_config.index_list_file_name)
    selected_directory = apk_path
    as_logger.info(f"Selected directory: {selected_directory}")
    if selected_directory == "":
        # exit(-1)
        as_logger.critical("[parse_mult_file()]: No APK path")
    apk_list = []
    for root, dirs, files in os.walk(selected_directory):
        for file in files:
            _, file_extension = os.path.splitext(file)
            if file_extension.lower() in as_config.accept_apk_extensions:
                apk_path = os.path.join(root, file)
                apk_list.append({"filename": file, "full_path": apk_path})
    as_logger.info(f"Found {len(apk_list)} {as_config.accept_apk_extensions}")
    if len(apk_list) != 0:
        finally_result = []
        for apk_item in apk_list:
            start_time = datetime.now() 
            record, result = _process_all(as_config, apk_item["full_path"], apk_item["filename"])
            finally_result = finally_result + result
            end_time = datetime.now()
            record["time_spent"] = (end_time - start_time).total_seconds()
            record["detect_time"] = end_time.strftime("%Y-%m-%d %H:%M:%S")
            _add_record(record_file_name, record)
    else:
        as_logger.warning(f"No {as_config.accept_apk_extensions} found!")
    as_logger.info(f"All APKs have been decoded and scanned, and the decoding completion time {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return _order_result(finally_result)
    
    
if __name__ == '__main__':
    print(parse_mult_file("/home/ApkScanner/ApkScannerLibrary/APK/test"))
