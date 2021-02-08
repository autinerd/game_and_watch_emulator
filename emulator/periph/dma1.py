from .periph import Periph

class DMA1(Periph):
    BASE_ADDR = 0x4002_0000

    def __init__(self):
        self._LISR = 0
        self._HISR = 0

        self._S0CR = 0
        self._S0NDTR = 0
        self._S0PAR = 0
        self._S0M0AR = 0
        self._S0M1AR = 0
        self._S0FCR = 0x21

    def read_mem(self, address: int, size: int) -> int:
        ...
        return 0

    def write_mem(self, address: int, size: int, data: int):
        ...
