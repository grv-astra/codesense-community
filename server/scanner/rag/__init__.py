# config.py or init.py
import logging
import warnings
import os

# Suppress warnings globally
warnings.filterwarnings("ignore")
os.environ["PYTHONWARNINGS"] = "ignore"

# Global logging config
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)

# Move the handler basicConfig() just installed behind a non-blocking queue --
# see log_queue.py's docstring for why (a hung write on that handler used to
# freeze every thread in the process, not just the one logging call).
from scanner.rag.log_queue import init_queued_logging  # noqa: E402
init_queued_logging()

# Reduce noise from third-party libs
for logger_name in ["urllib3", "requests"]:
    logging.getLogger(logger_name).setLevel(logging.ERROR)
