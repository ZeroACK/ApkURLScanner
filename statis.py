import os
import csv
import pandas as pd
from logger import as_logger, ASLogger
import re


ignore_file = ['apk_scan_index_list.csv', 'merged_unique_domains.csv']

def remove_port(domain):
    if isinstance(domain, str):
        return re.sub(r':\d+$', '', domain)
    return domain

def merge_and_deduplicate_domains(directory, file_full_path):
    all_domains = []
    for filename in os.listdir(directory):
        if filename.endswith('.csv') and filename not in ignore_file:
            filepath = os.path.join(directory, filename)
            as_logger.info(f'正在读取文件: {filepath}')
            data = pd.read_csv(filepath, usecols=['domain'])
            as_logger.info(f'文件 {filename} 包含的域名数: {len(data)}')
            data['domain'] = data['domain'].apply(remove_port)
            data['filename'] = filename
            all_domains.append(data)
    merged_data = pd.concat(all_domains, ignore_index=True)
    as_logger.info(f'去重前的域名总数: {len(merged_data)}')
    unique_domains = merged_data.drop_duplicates(subset='domain')
    as_logger.info(f'合并后去重的域名总数: {len(unique_domains)}')
    unique_domains.to_csv(file_full_path, index=False)
    as_logger.info(f'去重后的域名已保存到: {file_full_path}')

def list_apk_files(directory, file_full_path, extensions):
    apk_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            _, file_extension = os.path.splitext(file)
            if file_extension.lower() in extensions:
                apk_name = os.path.basename(file)
                category = os.path.basename(root)  # 使用上层目录名作为类别
                source_website = "unknown"
                if 'apkpure' in apk_name.lower():
                    source_website = 'https://apkpure.com/'
                else:
                    source_website = 'https://www.apkmirror.com/'
                apk_files.append([apk_name, category, source_website])
    with open(file_full_path, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["APK Name", "Category", "Source Website"])  # 修正列标题
        for apk_file in apk_files:
            writer.writerow(apk_file)
            
            