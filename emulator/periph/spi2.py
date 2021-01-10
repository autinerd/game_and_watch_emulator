from .periph import Periph

class SPI2(Periph):
    BASE_ADDR = 0x4000_3800

    def __init__(self):
        self._CR1 = 0
        self._CR2 = 0
        self._CFG1 = 0x7_0007
        self._CFG2 = 0
