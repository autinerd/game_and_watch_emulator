from unicorn import unicorn_const, Uc, arm_const
from .periph import *
import struct
import time
from queue import Queue
from . import consts
from threading import Lock

lcd_lock = Lock()
message_input_queue = Queue()
message_output_queue = Queue()
lcd_interrupt_queue = Queue()

lcd = ("LTDC", ltdc.LTDC(), 0x5000_1000, 0x5000_1FFF)

periphs = [
    ("FLASH", flash.FLASH(), 0x5200_2000, 0x5200_2FFF),
    ("RCC", rcc.RCC(), 0x5802_4400, 0x5802_47FF),
    ("PWR", pwr.PWR(), 0x5802_4800, 0x5802_4BFF),
    ("GPIOA", gpioa.GPIOA(), 0x5802_0000, 0x5802_03FF),
    ("GPIOB", gpiob.GPIOB(), 0x5802_0400, 0x5802_07FF),
    ("GPIOC", gpioc.GPIOC(), 0x5802_0800, 0x5802_0BFF),
    ("GPIOD", gpiod.GPIOD(), 0x5802_0C00, 0x5802_0FFF),
    ("GPIOE", gpioe.GPIOE(), 0x5802_1000, 0x5802_13FF),
    ("GPIOF", gpiof.GPIOF(), 0x5802_1400, 0x5802_17FF),
    ("GPIOG", gpiog.GPIOG(), 0x5802_1800, 0x5802_1BFF),
    ("GPIOH", gpioh.GPIOH(), 0x5802_1C00, 0x5802_1FFF),
    ("GPIOI", gpioi.GPIOI(), 0x5802_2000, 0x5802_23FF),
    ("GPIOJ", gpioj.GPIOJ(), 0x5802_2400, 0x5802_27FF),
    ("GPIOK", gpiok.GPIOK(), 0x5802_2800, 0x5802_2BFF),
    ("FMC", fmc.FMC(), 0x5200_4000, 0x5200_4FFF),
    lcd,
    ("RTC", rtc.RTC(), 0x5800_4000, 0x5800_43FF),
    ("SPI2", spi2.SPI2(), 0x4000_3800, 0x4000_3BFF),
    ("OCTOSPI1", octospi1.OCTOSPI1(), 0x5200_5000, 0x5200_5FFF),
    ("OCTOSPIM", octospim.OCTOSPIM(), 0x5200_B400, 0x5200_B7FF),
    ("TIM5", tim5.TIM5(), 0x4000_0C00, 0x4000_0FFF)
]

def hook_mem_read(mu: Uc, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_READ:
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                data = 0
                for periph in periphs:
                    if _between(address, periph[2], periph[3]):
                        data = periph[1].read_mem(address, size)
                        mu.mem_write(address, struct.pack('<L', data))
                        print(periph[0])
                        break
                print(f'access: read,  address: 0x{address:08X}, data: 0x{data:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
        elif access == unicorn_const.UC_MEM_READ_UNMAPPED:
            print(f'access unmapped memory: read,  address: 0x{address:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
    except KeyboardInterrupt:
        mu.emu_stop()
    
def hook_mem_write(mu: Uc, access, address, size, value, user_data):
    try:
        if access == unicorn_const.UC_MEM_WRITE:
            for periph in periphs:
                if _between(address, periph[2], periph[3]):
                    periph[1].write_mem(address, size, value)
                    print(periph[0])
                    break
            if address >= 0x4000_0000 and address <= 0x6000_0000:
                print(f'access: write, address: 0x{address:08X}, value: 0x{value:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
        elif access == unicorn_const.UC_MEM_WRITE_UNMAPPED:
            print(f'access unmapped memory: write,  address: 0x{address:08X}, value: 0x{value:08X}, pc: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}')
            print(f'data executed: {mu.mem_read(mu.reg_read(arm_const.UC_ARM_REG_PC), 4).hex()}')
    except KeyboardInterrupt:
        mu.emu_stop()


_interrupt_handler_mode = consts.INTERRUPT_NONE
_current_clock = time.monotonic_ns()
_saved_context = None
_last_pc_values = []

def hook_code(mu: Uc, address, size, user_data):
    global _current_clock
    global _interrupt_handler_mode
    global _saved_context
    global lcd
    global _last_pc_values

    _last_pc_values.append(mu.reg_read(arm_const.UC_ARM_REG_PC))
    if len(_last_pc_values) > 10:
        del _last_pc_values[0]

    try:
        if lcd[1]._ISR & 8 and _interrupt_handler_mode == consts.INTERRUPT_NONE:
            _saved_context = mu.context_save()
            _interrupt_handler_mode = consts.INTERRUPT_LTDC
            lcd_lock.acquire()
            print("Interrupt LCD")
            mu.reg_write(arm_const.UC_ARM_REG_PC, struct.unpack("<L", mu.mem_read(0x0800_01a0, 4))[0])
        elif time.monotonic_ns() - _current_clock > 1_000_000 and _interrupt_handler_mode == consts.INTERRUPT_NONE and address != 0x08010220:
            _current_clock = time.monotonic_ns()
            _interrupt_handler_mode = consts.INTERRUPT_SYSTICK
            _saved_context = mu.context_save()
            mu.reg_write(arm_const.UC_ARM_REG_PC, struct.unpack("<L", mu.mem_read(0x0800_003c, 4))[0])
        elif _interrupt_handler_mode > consts.INTERRUPT_NONE and mu.mem_read(address, 2) == b'\x70\x47':
            if lcd_lock.locked() and _interrupt_handler_mode == consts.INTERRUPT_LTDC:
                lcd_lock.release()
                print("Leave LCD interrupt")
            mu.context_restore(_saved_context)
            _saved_context = None
            mu.reg_write(arm_const.UC_ARM_REG_PC, mu.reg_read(arm_const.UC_ARM_REG_PC) + 1)
            _interrupt_handler_mode = consts.INTERRUPT_NONE
    except KeyboardInterrupt:
        mu.emu_stop()

def _between(val: int, min_val: int, max_val: int) -> bool:
    return val >= min_val and val <= max_val
