from unicorn import unicorn_const, Uc
from .periph import flash
import struct

FLASH = flash.FLASH()

def hook_mem_read(mu: Uc, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_READ:
            if _between(address, 0x5200_2000, 0x5200_2FFF):
                mu.mem_write(address, struct.pack('<l', FLASH.read_mem(address, size)))
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: read, address: 0x{address:08X}, size: {size}, value: 0x{value:08X}')
    except KeyboardInterrupt:
        mu.emu_stop()
    
def hook_mem_write(mu, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_WRITE:
            if _between(address, 0x5200_2000, 0x5200_2FFF):
                FLASH.write_mem(address, size, value)
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: write, address: 0x{address:08X}, size: {size}, value: 0x{value:08X}')
    except KeyboardInterrupt:
        mu.emu_stop()

def _between(val: int, min_val: int, max_val: int) -> bool:
    return val >= min_val and val <= max_val