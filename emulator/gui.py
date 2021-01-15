import tkinter
import time
from queue import Queue
from .mmu import periphs, lcd_lock
from .unicorn import arm_const, Uc
from struct import unpack
import os
from . import consts
import numpy
from PIL import Image, ImageTk
import threading

WIDTH, HEIGHT = 320, 240

class KeyTracker():
    last_press_time = {}
    last_release_time = {}

    def is_pressed(self, keysym):
        if not keysym in self.last_press_time:
            return False
        return time.time() - self.last_press_time[keysym] < .1

    def report_key_press(self, event):
        if not self.is_pressed(event.keysym):
            on_key_press(event)
        self.last_press_time[event.keysym] = time.time()

    def report_key_release(self, event):
        timer = threading.Timer(.1, self.report_key_release_callback, args=[event])
        timer.start()

    def report_key_release_callback(self, event):
        if not self.is_pressed(event.keysym):
            on_key_release(event)
        self.last_release_time[event.keysym] = time.time()

def convert_565(data: bytes) -> bytes:
    by = bytearray()
    for i in range(0, len(data), 2):
        val = unpack('<H', data[i:i+2])[0]
        r = (val >> 11) << 3
        g = ((val & 0b0000_0111_1110_0000) >> 5) << 2
        b = (val & 0b0000_0000_0001_1111) << 3
        by += bytearray([r, g, b])
    return bytes(by)

def on_key_press(e):
    print(f"key {e.keysym} down")

def on_key_release(e):
    print(f"key {e.keysym} up")

def on_closing():
    print("Closing window")
    import sys
    sys.stdout.flush()
    os._exit(0)

def GUIThread(message_input_queue: Queue, message_output_queue: Queue, mu: Uc):
    window = tkinter.Tk(className="Game and Watch Emulator")
    window.title = "Game and Watch Emulator"
    key_tracker = KeyTracker()
    window.bind_all('<KeyPress>', key_tracker.report_key_press)
    window.bind_all('<KeyRelease>', key_tracker.report_key_release)
    canvas = tkinter.Canvas(window, width=WIDTH, height=HEIGHT, bg="#000000")
    img = None
    label = tkinter.Label(window, text="Test")
    canvas.pack()
    label.pack()
    window.protocol("WM_DELETE_WINDOW", on_closing)

    sync_height = 7
    sync_width = 60

    scale = 3

    old_data = None

    old_width = 0
    old_height = 0

    t = time.monotonic_ns()

    while True:
        if time.monotonic_ns() - t < 1_000_000_000 / 60:
            time.sleep(0.01)
            continue
        t = time.monotonic_ns()
        with lcd_lock:
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
            if width > 0 and height > 0 and (old_width != width or old_height != height):
                canvas.configure(width=(window_width-sync_width)*scale, height=(window_height-sync_height)*scale)
                old_height = height
                old_width = width
            if ltdc._GCR & 1 and ltdc._L1CR & 1:
                data = mu.mem_read(fb_addr, fb_line_length*height)
                if old_data != data:
                    img = ImageTk.PhotoImage(image=Image.frombytes("RGB", (width, height), convert_565(data)).resize(((window_width-sync_width)*scale, (window_height-sync_height)*scale)))
                    canvas.create_image((window_width-sync_width)*scale/2, (window_height-sync_height)*scale/2, image=img)
                    old_data = data

                    if ltdc._IER & 8:
                        print("Put interrupt")
                        ltdc._ISR |= 8
        label.configure(text=f"LTDC on: {bool(ltdc._GCR & 1)}, Pixel format: {ltdc._L1PFCR}, default color: 0x{ltdc._L1DCCR:08X}, PC: 0x{mu.reg_read(arm_const.UC_ARM_REG_PC):08X}\nFramebuffer 1: 0x{fb_addr:08X}, Framebuffer 1 width: {width}, framebuffer height: {height}\n" + 
        f"X1: {ltdc._L1WHPCR & 0xFFFF}, X2: {ltdc._L1WHPCR >> 16}, Y1: {ltdc._L1WVPCR & 0xFFFF}, Y2: {ltdc._L1WVPCR >> 16}\n" + 
        f"Layer 1 enabled: {bool(ltdc._L1CR & 1)}, Layer 2 enabled: {bool(ltdc._L2CR & 1)}, Interrupt enabled: {ltdc._IER}")
        window.update_idletasks()
        window.update()
