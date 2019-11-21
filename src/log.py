import logging

logging.SUCCESS = 25  # between WARNING and INFO
logging.addLevelName(logging.SUCCESS, 'SUCCESS')

logging.VERBOSE = 5  # between NOTSET and DEBUG
logging.addLevelName(logging.VERBOSE, 'VERBOSE')

from logging import (
    FileHandler,
    Formatter,
    getLevelName,
    VERBOSE,
    DEBUG, 
    INFO,
    SUCCESS,
    WARN,
    ERROR,
    FATAL,
    CRITICAL
)


def getLogger(name = None):
    """
    Install Log class as default logging class and returns new or existing logger by name.
    Note: this will install Log as default logging class for all loggers
    """
    if logging.getLoggerClass() != Log:
        logging.setLoggerClass(Log)
    return logging.getLogger(name)

class Log(logging.Logger):
    def success(self, msg, *args, **kw):
        if self.isEnabledFor(SUCCESS):
            self._log(SUCCESS, msg, args, **kw)

    def verbose(self, msg, *args, **kw):
        if self.isEnabledFor(VERBOSE):
            self._log(VERBOSE, msg, args, **kw)