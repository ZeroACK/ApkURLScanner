import configparser


class ASConfig:
    def __init__(self, config_file):
        self.config = configparser.RawConfigParser()
        self._read_config(config_file)

    def _read_config(self, config_file):
        self.config.read(config_file)
        self.store_apk_path = self._get_config('Paths', 'STORE_APK_PATH')
        self.decode_apk_path = self._get_config('Paths', 'DECODE_APK_PATH')
        self.library_path = self._get_config('Paths', 'LIBRARY_PATH')
        self.result_path = self._get_config('Paths', 'RESULT_PATH')
        self.statistics_path = self._get_config('Paths', 'STATISTICS_PATH')
        
        self.domain_file_name = self._get_config('Files', 'DOMAIN_FILE_NAME')
        self.has_ipv6_file_name = self._get_config('Files', 'HAS_IPV6_FILE_NAME')
        self.non_existent_file_name = self._get_config('Files', 'NON_EXISTENT_FILE_NAME')
        self.index_list_file_name = self._get_config('Files', 'INDEX_LIST_FILE_NAME')
        self.order_file_name = self._get_config('Files', 'ORDER_FILE_NAME')
        self.statistics_apk_file_name = self._get_config('Files', 'STATISTICS_APK_FILE_NAME')
        
        self.skip_dirs = self._get_config('Settings', 'SKIP_DIRS', list_type=True)
        self.nameservers = self._get_config('Settings', 'NAMESERVERS', list_type=True)
        self.scan_extensions = self._get_config('Settings', 'SCAN_EXTENSIONS', list_type=True)
        self.accept_apk_extensions = self._get_config('Settings', 'ACCEPT_APK_EXTENSION', list_type=True)
        
        self.log_directory = self._get_config('Logging', 'LOG_DIRECTORY')
        self.log_filename = self._get_config('Logging', 'LOG_FILENAME')
        self.log_format = self._get_config('Logging', 'LOG_FORMAT')
        self.console_log_level = self._get_config('Logging', 'CONSOLE_LOG_LEVEL').upper()
        self.file_log_level = self._get_config('Logging', 'FILE_LOG_LEVEL').upper()

    def _get_config(self, section, option, list_type=False):
        if list_type:
            return self.config.get(section, option).split(',')
        return self.config.get(section, option)

    def reload(self, config_file):
        self._read_config(config_file)
        
    def display(self):
        print(f"DECODE_APK_PATH: {self.decode_apk_path}")
        print(f"RESULT_PATH: {self.result_path}")
        print(f"DOMAIN_FILE_NAME: {self.domain_file_name}")
        print(f"HAS_IPV6_FILE_NAME: {self.has_ipv6_file_name}")
        print(f"NON_EXISTENT_FILE_NAME: {self.non_existent_file_name}")
        print(f"SKIP_DIRS: {self.skip_dirs}")
        print(f"NAMESERVERS: {self.nameservers}")
        print(f"SCAN_EXTENSIONS: {self.scan_extensions}")
        print(f"ACCEPT_APK_EXTENSIONS: {self.accept_apk_extensions}")  # Add this line for ACCEPT_APK_EXTENSION
        print(f"LOG_DIRECTORY: {self.log_directory}")
        print(f"LOG_FILENAME: {self.log_filename}")
        print(f"LOG_FORMAT: {self.log_format}")
        print(f"CONSOLE_LOG_LEVEL: {self.console_log_level}")  # Use console_log_level
        print(f"FILE_LOG_LEVEL: {self.file_log_level}")  # Use file_log_level
