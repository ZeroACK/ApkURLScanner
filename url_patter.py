import os
import re
import chardet
import sys
from logger import as_logger


def find_urls_in_file(file_path):
    url_pattern = re.compile(r'\b(?:https?://)?(?:www\.)?(?:[\w-]+\.)+[\w-]+(?::\d{1,5})?(?:/[^\s\"<>{}|\\^`]*?)?\b')
    urls_found = set()
    with open(file_path, 'rb') as file:
        raw_data = file.read()
    encoding = chardet.detect(raw_data)['encoding']
    as_logger.debug(f"Scanner: {file_path}, Decode: {encoding}")
    sys.stdout.flush()
    with open(file_path, 'r', encoding=encoding) as file:
        for line in file:
            urls = url_pattern.findall(line)
            if urls:
                urls_found.update(urls)
    return urls_found


def scan_folder_for_urls(folder_path, skip_dirs, allowed_extensions):
    urls_in_folder = {}
    for root, dirs, files in os.walk(folder_path, topdown=True):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for file in files:
            if any(file.endswith(ext) for ext in allowed_extensions):
                file_path = os.path.join(root, file)
                try:
                    urls_in_folder[file_path] = find_urls_in_file(file_path)
                except:
                    as_logger.warning(f" Find url in {file_path} failed.")
    return urls_in_folder
