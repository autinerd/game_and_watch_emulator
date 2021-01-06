import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, Gdk, GdkPixbuf
import cairo
from queue import Queue
from . import consts

class DrawingAreaFrame(Gtk.Frame):
    def __init__(self, css=None, border_width=0, message_input_queue: Queue = None, message_output_queue: Queue = None):
        super().__init__()
        self.set_border_width(border_width)
        self.set_size_request(100, 100)
        self.vexpand = True
        self.hexpand = True
        self.surface = None
        self.message_input_queue = message_input_queue
        self.message_output_queue = message_output_queue

        self.area = Gtk.DrawingArea()
        self.add(self.area)

        self.area.connect("draw", self.on_draw)
        self.area.connect('configure-event', self.on_configure)

    def on_key_press_event(self, widget: Gtk.Widget, event):
        if event.keyval == Gdk.KEY_uparrow:
            self.message_input_queue.put(consts.INPUT_UP)

    def init_surface(self, area):
        # Destroy previous buffer
        if self.surface is not None:
            self.surface.finish()
            self.surface = None

        # Create a new buffer
        self.surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, area.get_allocated_width(), area.get_allocated_height())

    def redraw(self): 
        self.init_surface(self.area)
        context = cairo.Context(self.surface)
        context.scale(self.surface.get_width(), self.surface.get_height())
        self.do_drawing(context)
        self.surface.flush()

    def on_configure(self, area, event, data=None): 
        self.redraw()
        return False

    def on_draw(self, area, context):
        if self.surface is not None:
            context.set_source_surface(self.surface, 0.0, 0.0)            
            context.paint()
        else:
            print('Invalid surface')
        return False

    def draw_radial_gradient_rect(self, ctx):
        x0, y0 = 0.3, 0.3
        x1, y1 = 0.5, 0.5
        r0 = 0
        r1 = 1        
        pattern = cairo.RadialGradient(x0, y0, r0, x1, y1, r1) 
        pattern.add_color_stop_rgba(0, 1,1,0.5, 1)   
        pattern.add_color_stop_rgba(1, 0.2,0.4,0.1, 1)   
        ctx.rectangle(0, 0, 1, 1)       
        ctx.set_source(pattern)
        ctx.fill()         

    def do_drawing(self, ctx):
        self.draw_radial_gradient_rect(ctx)        

class Window(Gtk.Window):
    def __init__(self, message_input_queue: Queue = None, message_output_queue: Queue = None):
        Gtk.Window.__init__(self)
        self.set_title("Test Draw Radial Gradient")
        self.set_default_size(800, 600)
        self.connect("destroy", Gtk.main_quit)    

        frame = DrawingAreaFrame(message_input_queue=message_input_queue, message_output_queue=message_output_queue)        
        self.add(frame)

def GUIThread(message_input_queue: Queue, message_output_queue: Queue):
    window = Window(message_input_queue=message_input_queue, message_output_queue=message_output_queue)
    window.show_all()
    Gtk.main()