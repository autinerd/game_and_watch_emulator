import tkinter
import time
from math import sin
from queue import Queue
from .mmu import periphs
from .unicorn import arm_const, Uc
from struct import unpack

WIDTH, HEIGHT = 640, 480

def convert_565(val: int) -> str:
    r = (val >> 11) << 3
    g = ((val & 0b0000_0111_1110_0000) >> 5) << 2
    b = (val & 0b0000_0000_0001_1111) << 3
    return f'#{r:02x}{g:02x}{b:02x}'

def GUIThread(message_input_queue: Queue, message_output_queue: Queue, mu: Uc):
    window = tkinter.Tk(className="Game and Watch Emulator")
    window.title = "Game and Watch Emulator"
    canvas = tkinter.Canvas(window, width=WIDTH, height=HEIGHT, bg="#000000")
    label = tkinter.Label(window, text="Test")
    canvas.pack()
    label.pack()

    pic = False

    sync_height = 8
    sync_width = 61

    scale = 3

    while True:
        time.sleep(1)
        old_data = None
        ltdc = [p for p in periphs if p[0] == 'LTDC'][0][1]
        window_width = ltdc._AWCR >> 16
        window_height = ltdc._AWCR & 0xFFFF
        X1 = ltdc._L1WHPCR & 0xFFFF
        X2 = ltdc._L1WHPCR >> 16
        Y1 = ltdc._L1WVPCR & 0xFFFF
        Y2 = ltdc._L1WVPCR >> 16
        fb_addr = ltdc._L1CFBAR
        fb_line_length = ltdc._L1CFBLR >> 16
        width = fb_line_length // 2
        height = ltdc._L1CFBLNR


        if width > 0 and height > 0:
            canvas.configure(width=(window_width-sync_width)*scale, height=(window_height-sync_height)*scale)
        if ltdc._GCR & 1:
            data = mu.mem_read(fb_addr, fb_line_length*height)
            if old_data != data:
                canvas.delete("a")
                old_data = data
                a = [convert_565(unpack('<H', data[i:i+2])[0]) for i in range(0, len(data), 2)]
                for y in range(sync_height, window_height):
                    for x in range(sync_width, window_width):
                        if x < X1 or y < Y1 or x > X2 or y > Y2:
                            canvas.create_rectangle((x-sync_width)*scale, (y-sync_height)*scale, (x-sync_width)*scale+(scale-1), (y-sync_height)*scale+(scale-1), outline="white", fill=f"#{ltdc._L1DCCR & 0xFF_FFFF:06X}", tags="a", width=0)
                        else:
                            c = a[(y-Y1)*width + (x-X1)]
                            canvas.create_rectangle((x-sync_width)*scale, (y-sync_height)*scale, (x-sync_width)*scale+(scale-1), (y-sync_height)*scale+(scale-1), outline="white", fill=c, tags="a", width=0)
        label.configure(text=f"LTDC on: {bool(ltdc._GCR & 1)}, Pixel format: {ltdc._L1PFCR}, default color: 0x{ltdc._L1DCCR:08X}, PC: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}\nFramebuffer 1: 0x{fb_addr:08X}, Framebuffer 1 width: {width}, framebuffer height: {height}\n" + 
        f"X1: {ltdc._L1WHPCR & 0xFFFF}, X2: {ltdc._L1WHPCR >> 16}, Y1: {ltdc._L1WVPCR & 0xFFFF}, Y2: {ltdc._L1WVPCR >> 16}\n" + 
        f"Layer 1 enabled: {bool(ltdc._L1CR & 1)}, Layer 2 enabled: {bool(ltdc._L2CR & 1)}, Dithering enabled: {bool(ltdc._GCR & 0x1_0000)}")
        window.update_idletasks()
        window.update()
