#
# Copyright (C) 2010, 2011 Vinay Sajip. All rights reserved.
#
import logging
import os

class ColorizingStreamHandler(logging.StreamHandler):
    # color names to indices
    color_map = {
        'black': 0,
        'red': 1,
        'green': 2,
        'yellow': 3,
        'blue': 4,
        'magenta': 5,
        'cyan': 6,
        'white': 7,
    }

    #levels to (background, foreground, bold/intense)
    level_map = {
        #logging.DEBUG: (None, 'blue', False),
        logging.DEBUG: (None, 'white', False),
        logging.INFO: (None, 'blue', False),
        logging.WARNING: (None, 'yellow', False),
        logging.ERROR: (None, 'red', False),
        logging.CRITICAL: ('red', 'white', True),
    }
    csi = '\x1b['
    reset = '\x1b[0m'

    @property
    def is_tty(self):
        isatty = getattr(self.stream, 'isatty', None)
        return isatty and isatty()

    def emit(self, record):
        try:
            message = self.format(record)
            stream = self.stream
            stream.write(message)
            stream.write(getattr(self, 'terminator', '\n'))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def output_colorized(self, message):
        self.stream.write(message)

    def colorize(self, message, record):
        if record.levelno in self.level_map:
            bg, fg, bold = self.level_map[record.levelno]
            params = []
            if bg in self.color_map:
                params.append(str(self.color_map[bg] + 40))
            if fg in self.color_map:
                params.append(str(self.color_map[fg] + 30))
            if bold:
                params.append('1')
            if params:
                message = ''.join((self.csi, ';'.join(params),
                                   'm', message, self.reset))
        return message

    def format(self, record):
        message = logging.StreamHandler.format(self, record)
        if self.is_tty:
            # Don't colorize any traceback
            parts = message.split('\n', 1)
            parts[0] = self.colorize(parts[0], record)
            message = '\n'.join(parts)
        return message

def main():
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(ColorizingStreamHandler())
    logging.debug('DEBUG')
    logging.info('INFO')
    logging.warning('WARNING')
    logging.error('ERROR')
    logging.critical('CRITICAL')

def init_log(log_level):
    """log_level = logging.NOTSET logging.DEBUG logging.INFO logging.ERROR logging.CRITICAL"""
    root = logging.getLogger()
    root.setLevel(log_level)
    stream_handler = ColorizingStreamHandler()
    formatter = logging.Formatter('[%(funcName)-10s %(lineno)d %(levelname)-8s] %(message)s')
    #logging.StreamHandler.setFormatter(formatter)

    stream_handler.setFormatter(formatter)
    #root.addHandler(ColorizingStreamHandler())
    root.addHandler(stream_handler)
    return root
    
if __name__ == '__main__':
   # main()
    logger = init_log(logging.DEBUG)
    logger.debug('DEBUG..........................')
    logger.info('INFO----------------------------') 
    logger.warning('WARNING======================')
    logger.error('ERROR**************************')
    logger.error('ERROR**************************%r' %({'value':'111'}))
    #logger.error('ERROR**************************', {'value':'111'})
