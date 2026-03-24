import shutil
import zipfile
import subprocess
import os
import threading
from logger import as_logger


def check_zip_header(apk_path):
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            corrupt_file = zip_ref.testzip()
            if corrupt_file is not None:
                print(f"Corrupt file found: {corrupt_file}")
                return False
            # print("ZIP file header is correct.")
            return True
    except zipfile.BadZipFile:
        as_logger.warning("Bad ZIP file.")
        return False
    except Exception as e:
        as_logger.warning(f"An unexpected error occurred while checking ZIP header: {str(e)}")
        return False

def read_stream(stream, logger_method):
    try:
        for line in iter(stream.readline, ''):
            logger_method(line.strip())
    finally:
        stream.close()
        
def run_apktool(apk_fpath, output_folder, timeout=3600):
    java_exe = "java"
    java_home = os.getenv('JAVA_HOME')
    if java_home:
        java_exe = f"{java_home}/bin/java"
    jar_path = "apktool.jar"
    cmd = [
        java_exe, "-jar", "-Xmx1024M", "-Duser.language=en", "-Dfile.encoding=UTF8",
        "-Djdk.util.zip.disableZip64ExtraFieldValidation=true", "-Djdk.nio.zipfs.allowDotZipEntry=true",
        jar_path, "--advanced", "decode", apk_fpath, "-o", output_folder, "--force",
    ]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, as_logger.debug))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, as_logger.error))
        stdout_thread.start()
        stderr_thread.start()
        process.wait(timeout=timeout)
        stdout_thread.join()
        stderr_thread.join()
        if process.returncode != 0:
            as_logger.error(f"Decoding \"{apk_fpath}\" partially completed with errors!")
            return False
        else:
            as_logger.info(f"Decoding \"{apk_fpath}\" successfully.")
            return True
    except subprocess.TimeoutExpired:
        process.kill()
        as_logger.error(f"Decoding \"{apk_fpath}\" was killed due to timeout after {timeout} seconds.")
        return False
    except subprocess.CalledProcessError as e:
        as_logger.error("Decoding failed due to a subprocess error.")
        as_logger.warning(e.stderr)
        return False
    except Exception as e:
        as_logger.error("An unexpected error occurred.")
        as_logger.warning(str(e))
        return False
    finally:
        if process:
            process.kill()  # Ensure the process is terminated


def decode_apk(apk_path, output_dir):
    if not check_zip_header(apk_path):
        as_logger.warning("ZIP header check failed. Skipping decoding.")
        return False
    run_apktool(apk_path, output_dir)
    return True


def decode_xapk(apk_path, apks_store_path, output_dir):
    if not check_zip_header(apk_path):
        as_logger.warning("ZIP header check failed. Skipping decoding.")
        return []
    run_apktool(apk_path, output_dir)
    os.makedirs(apks_store_path, exist_ok=True)
    moved_files = []
    for root, dirs, files in os.walk(os.path.join(output_dir, "unknown")):
        for file in files:
            if file.endswith(".apk"):
                src_path = os.path.join(root, file)
                dest_path = os.path.join(apks_store_path, file)
                shutil.move(src_path, dest_path)
                moved_files.append(dest_path)
    return moved_files
