import logging
import os
import sys
from datetime import datetime


class StreamToLogger:
    def __init__(self, logger, log_level=logging.INFO):
        self.logger = logger
        self.log_level = log_level
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.log_level, line.rstrip())

    def flush(self):
        pass


class ASLogger:

    logger = logging.getLogger(__name__)

    def __init__(self):
        self.current_log_file_name = ""
        self.logger = logging.getLogger(__name__)

    def setup_logger(self, config):
        timestamp = datetime.now()
        formatted_date = timestamp.strftime("%Y%m%d")
        temp_log_file_name = config.log_filename.replace("%(asctime)s", formatted_date)
        if self.current_log_file_name != temp_log_file_name:
            self.current_log_file_name = temp_log_file_name
            os.makedirs(config.log_directory, exist_ok=True)
            log_path = os.path.join(config.log_directory, self.current_log_file_name)
            logging.basicConfig(level=getattr(logging, config.console_log_level), format=config.log_format, handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ])
            sys.stdout = StreamToLogger(logging.getLogger(), logging.INFO)
            sys.stderr = StreamToLogger(logging.getLogger(), logging.ERROR)

    def debug(self, log_str):
        self.logger.debug(log_str)

    def info(self, log_str):
        self.logger.info(log_str)

    def warning(self, log_str):
        self.logger.warning(log_str)

    def error(self, log_str):
        self.logger.error(log_str)

    def critical(self, log_str):
        self.logger.critical(log_str)


as_logger = ASLogger.logger
