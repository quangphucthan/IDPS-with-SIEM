import signal

_STOP = {"flag": False}

def _handler(signum, frame):
    _STOP["flag"] = True

def install_sigint_handler():
    signal.signal(signal.SIGINT, _handler)
    return _STOP
