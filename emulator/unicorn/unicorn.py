# Unicorn Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
import ctypes.util
import distutils.sysconfig
import pkg_resources
import inspect
import os.path
import sys
import weakref

from . import unicorn_const as uc

if not hasattr(sys.modules[__name__], "__file__"):
    __file__ = inspect.getfile(inspect.currentframe())

_lib = { 'darwin': 'libunicorn.dylib',
         'win32': 'unicorn.dll',
         'cygwin': 'cygunicorn.dll',
         'linux': 'libunicorn.so',
         'linux2': 'libunicorn.so' }


# Windows DLL in dependency order
_all_windows_dlls = (
    "libwinpthread-1.dll",
    "libgcc_s_seh-1.dll",
    "libgcc_s_dw2-1.dll",
)

_loaded_windows_dlls = set()

def _load_win_support(path):
    for dll in _all_windows_dlls:
        if dll in _loaded_windows_dlls:
            continue

        lib_file = os.path.join(path, dll)
        if ('/' not in path and '\\' not in path) or os.path.exists(lib_file):
            try:
                #print('Trying to load Windows library', lib_file)
                ctypes.cdll.LoadLibrary(lib_file)
                #print('SUCCESS')
                _loaded_windows_dlls.add(dll)
            except OSError as e:
                #print('FAIL to load %s' %lib_file, e)
                continue

# Initial attempt: load all dlls globally
if sys.platform in ('win32', 'cygwin'):
    _load_win_support('')

def _load_lib(path):
    try:
        if sys.platform in ('win32', 'cygwin'):
            _load_win_support(path)

        lib_file = os.path.join(path, _lib.get(sys.platform, 'libunicorn.so'))
        #print('Trying to load shared library', lib_file)
        dll = ctypes.cdll.LoadLibrary(lib_file)
        #print('SUCCESS')
        return dll
    except OSError as e:
        #print('FAIL to load %s' %lib_file, e)
        return None

_uc = None

# Loading attempts, in order
# - user-provided environment variable
# - pkg_resources can get us the path to the local libraries
# - we can get the path to the local libraries by parsing our filename
# - global load
# - python's lib directory
# - last-gasp attempt at some hardcoded paths on darwin and linux

_path_list = [os.getenv('LIBUNICORN_PATH', None),
              pkg_resources.resource_filename(__name__, 'lib'),
              os.path.join(os.path.split(__file__)[0], 'lib'),
              '',
              distutils.sysconfig.get_python_lib(),
              "/usr/local/lib/" if sys.platform == 'darwin' else '/usr/lib64',
              os.getenv('PATH', '')]

for _path in _path_list:
    if _path is None: continue
    _uc = _load_lib(_path)
    if _uc is not None: break
else:
    raise ImportError("ERROR: fail to load the dynamic library.")

__version__ = "%u.%u.%u" % (uc.UC_VERSION_MAJOR, uc.UC_VERSION_MINOR, uc.UC_VERSION_EXTRA)

# setup all the function prototype
def _setup_prototype(lib, fname, restype, *argtypes):
    getattr(lib, fname).restype = restype
    getattr(lib, fname).argtypes = argtypes

ucerr = ctypes.c_int
uc_engine = ctypes.c_void_p
uc_context = ctypes.c_void_p
uc_hook_h = ctypes.c_size_t

class _uc_mem_region(ctypes.Structure):
    _fields_ = [
        ("begin", ctypes.c_uint64),
        ("end",   ctypes.c_uint64),
        ("perms", ctypes.c_uint32),
    ]


_setup_prototype(_uc, "uc_version", ctypes.c_uint, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
_setup_prototype(_uc, "uc_arch_supported", ctypes.c_bool, ctypes.c_int)
_setup_prototype(_uc, "uc_open", ucerr, ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(uc_engine))
_setup_prototype(_uc, "uc_close", ucerr, uc_engine)
_setup_prototype(_uc, "uc_strerror", ctypes.c_char_p, ucerr)
_setup_prototype(_uc, "uc_errno", ucerr, uc_engine)
_setup_prototype(_uc, "uc_reg_read", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_reg_write", ucerr, uc_engine, ctypes.c_int, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_read", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_write", ucerr, uc_engine, ctypes.c_uint64, ctypes.POINTER(ctypes.c_char), ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_start", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_emu_stop", ucerr, uc_engine)
_setup_prototype(_uc, "uc_hook_del", ucerr, uc_engine, uc_hook_h)
_setup_prototype(_uc, "uc_mem_map", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_mem_map_ptr", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p)
_setup_prototype(_uc, "uc_mem_unmap", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t)
_setup_prototype(_uc, "uc_mem_protect", ucerr, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_uint32)
_setup_prototype(_uc, "uc_query", ucerr, uc_engine, ctypes.c_uint32, ctypes.POINTER(ctypes.c_size_t))
_setup_prototype(_uc, "uc_context_alloc", ucerr, uc_engine, ctypes.POINTER(uc_context))
_setup_prototype(_uc, "uc_free", ucerr, ctypes.c_void_p)
_setup_prototype(_uc, "uc_context_save", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_restore", ucerr, uc_engine, uc_context)
_setup_prototype(_uc, "uc_context_size", ctypes.c_size_t, uc_engine)
_setup_prototype(_uc, "uc_context_free", ucerr, uc_context)
_setup_prototype(_uc, "uc_mem_regions", ucerr, uc_engine, ctypes.POINTER(ctypes.POINTER(_uc_mem_region)), ctypes.POINTER(ctypes.c_uint32))

# uc_hook_add is special due to variable number of arguments
_uc.uc_hook_add = _uc.uc_hook_add
_uc.uc_hook_add.restype = ucerr

UC_HOOK_CODE_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_uint64, ctypes.c_size_t, ctypes.c_void_p)
UC_HOOK_INSN_INVALID_CB = ctypes.CFUNCTYPE(ctypes.c_bool, uc_engine, ctypes.c_void_p)
UC_HOOK_MEM_INVALID_CB = ctypes.CFUNCTYPE(
    ctypes.c_bool, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_MEM_ACCESS_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_int,
    ctypes.c_uint64, ctypes.c_int, ctypes.c_int64, ctypes.c_void_p
)
UC_HOOK_INTR_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_IN_CB = ctypes.CFUNCTYPE(
    ctypes.c_uint32, uc_engine, ctypes.c_uint32, ctypes.c_int, ctypes.c_void_p
)
UC_HOOK_INSN_OUT_CB = ctypes.CFUNCTYPE(
    None, uc_engine, ctypes.c_uint32,
    ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p
)
UC_HOOK_INSN_SYSCALL_CB = ctypes.CFUNCTYPE(None, uc_engine, ctypes.c_void_p)


# access to error code via @errno of UcError
class UcError(Exception):
    def __init__(self, errno):
        self.errno = errno

    def __str__(self):
        return _uc.uc_strerror(self.errno).decode('ascii')


# return the core's version
def uc_version():
    major = ctypes.c_int()
    minor = ctypes.c_int()
    combined = _uc.uc_version(ctypes.byref(major), ctypes.byref(minor))
    return (major.value, minor.value, combined)


# return the binding's version
def version_bind():
    return (
        uc.UC_API_MAJOR, uc.UC_API_MINOR,
        (uc.UC_API_MAJOR << 8) + uc.UC_API_MINOR,
    )


# check to see if this engine supports a particular arch
def uc_arch_supported(query: int):
    return _uc.uc_arch_supported(query)

# Subclassing ref to allow property assignment.
class UcRef(weakref.ref):
    pass

# This class tracks Uc instance destruction and releases handles.
class UcCleanupManager(object):
    def __init__(self):
        self._refs = {}

    def register(self, uc):
        ref = UcRef(uc, self._finalizer)
        ref._uch = uc._uch
        ref._class = uc.__class__
        self._refs[id(ref)] = ref

    def _finalizer(self, ref):
        # note: this method must be completely self-contained and cannot have any references
        # to anything else in this module.
        #
        # This is because it may be called late in the Python interpreter's shutdown phase, at
        # which point the module's variables may already have been deinitialized and set to None.
        #
        # Not respecting that can lead to errors such as:
        #     Exception AttributeError:
        #       "'NoneType' object has no attribute 'release_handle'"
        #       in <bound method UcCleanupManager._finalizer of
        #       <unicorn.unicorn.UcCleanupManager object at 0x7f0bb83e4310>> ignored
        #
        # For that reason, we do not try to access the `Uc` class directly here but instead use
        # the saved `._class` reference.
        del self._refs[id(ref)]
        ref._class.release_handle(ref._uch)

class Uc(object):
    _cleanup = UcCleanupManager()

    def __init__(self, arch, mode):
        # verify version compatibility with the core before doing anything
        (major, minor, _combined) = uc_version()
        if major != uc.UC_API_MAJOR or minor != uc.UC_API_MINOR:
            self._uch = None
            # our binding version is different from the core's API version
            raise UcError(uc.UC_ERR_VERSION)

        self._arch, self._mode = arch, mode
        self._uch = ctypes.c_void_p()
        status = _uc.uc_open(arch, mode, ctypes.byref(self._uch))
        if status != uc.UC_ERR_OK:
            self._uch = None
            raise UcError(status)
        # internal mapping table to save callback & userdata
        self._callbacks = {}
        self._ctype_cbs = {}
        self._callback_count = 0
        self._cleanup.register(self)

    @staticmethod
    def release_handle(uch):
        if uch:
            try:
                status = _uc.uc_close(uch)
                if status != uc.UC_ERR_OK:
                    raise UcError(status)
            except:  # _uc might be pulled from under our feet
                pass

    # emulate from @begin, and stop when reaching address @until
    def emu_start(self, begin, until, timeout=0, count=0):
        status = _uc.uc_emu_start(self._uch, begin, until, timeout, count)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # stop emulation
    def emu_stop(self):
        status = _uc.uc_emu_stop(self._uch)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return the value of a register
    def reg_read(self, reg_id, opt=None):

        # read to 64bit number to be safe
        reg = ctypes.c_uint64(0)
        status = _uc.uc_reg_read(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return reg.value

    # write to a register
    def reg_write(self, reg_id, value):
        reg = None

        if reg is None:
            # convert to 64bit number to be safe
            reg = ctypes.c_uint64(value)

        status = _uc.uc_reg_write(self._uch, reg_id, ctypes.byref(reg))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # read data from memory
    def mem_read(self, address, size):
        data = ctypes.create_string_buffer(size)
        status = _uc.uc_mem_read(self._uch, address, data, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return bytearray(data)

    # write to memory
    def mem_write(self, address: int, data: bytes):
        status = _uc.uc_mem_write(self._uch, address, data, len(data))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory
    def mem_map(self, address: int, size: int, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_map(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # map a range of memory from a raw host memory address
    def mem_map_ptr(self, address: int, size: int, perms, ptr):
        status = _uc.uc_mem_map_ptr(self._uch, address, size, perms, ptr)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # unmap a range of memory
    def mem_unmap(self, address: int, size: int):
        status = _uc.uc_mem_unmap(self._uch, address, size)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # protect a range of memory
    def mem_protect(self, address, size, perms=uc.UC_PROT_ALL):
        status = _uc.uc_mem_protect(self._uch, address, size, perms)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # return CPU mode at runtime
    def query(self, query_mode):
        result = ctypes.c_size_t(0)
        status = _uc.uc_query(self._uch, query_mode, ctypes.byref(result))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        return result.value

    def _hookcode_cb(self, handle, address, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, address, size, data)

    def _hook_mem_invalid_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, access, address, size, value, data)

    def _hook_mem_access_cb(self, handle, access, address, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, access, address, size, value, data)

    def _hook_intr_cb(self, handle, intno, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, intno, data)

    def _hook_insn_invalid_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, data)

    def _hook_insn_in_cb(self, handle, port, size, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        return cb(self, port, size, data)

    def _hook_insn_out_cb(self, handle, port, size, value, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, port, size, value, data)

    def _hook_insn_syscall_cb(self, handle, user_data):
        # call user's callback with self object
        (cb, data) = self._callbacks[user_data]
        cb(self, data)

    # add a hook
    def hook_add(self, htype, callback, user_data=None, begin=1, end=0, arg1=0):
        _h2 = uc_hook_h()

        # save callback & user_data
        self._callback_count += 1
        self._callbacks[self._callback_count] = (callback, user_data)
        cb = None

        if htype == uc.UC_HOOK_INSN:
            insn = ctypes.c_int(arg1)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end), insn
            )
        elif htype == uc.UC_HOOK_INTR:
            cb = ctypes.cast(UC_HOOK_INTR_CB(self._hook_intr_cb), UC_HOOK_INTR_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        elif htype == uc.UC_HOOK_INSN_INVALID:
            cb = ctypes.cast(UC_HOOK_INSN_INVALID_CB(self._hook_insn_invalid_cb), UC_HOOK_INSN_INVALID_CB)
            status = _uc.uc_hook_add(
                self._uch, ctypes.byref(_h2), htype, cb,
                ctypes.cast(self._callback_count, ctypes.c_void_p),
                ctypes.c_uint64(begin), ctypes.c_uint64(end)
            )
        else:
            if htype in (uc.UC_HOOK_BLOCK, uc.UC_HOOK_CODE):
                # set callback with wrapper, so it can be called
                # with this object as param
                cb = ctypes.cast(UC_HOOK_CODE_CB(self._hookcode_cb), UC_HOOK_CODE_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            elif htype & (uc.UC_HOOK_MEM_READ_UNMAPPED |
                          uc.UC_HOOK_MEM_WRITE_UNMAPPED |
                          uc.UC_HOOK_MEM_FETCH_UNMAPPED |
                          uc.UC_HOOK_MEM_READ_PROT |
                          uc.UC_HOOK_MEM_WRITE_PROT |
                          uc.UC_HOOK_MEM_FETCH_PROT):
                cb = ctypes.cast(UC_HOOK_MEM_INVALID_CB(self._hook_mem_invalid_cb), UC_HOOK_MEM_INVALID_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )
            else:
                cb = ctypes.cast(UC_HOOK_MEM_ACCESS_CB(self._hook_mem_access_cb), UC_HOOK_MEM_ACCESS_CB)
                status = _uc.uc_hook_add(
                    self._uch, ctypes.byref(_h2), htype, cb,
                    ctypes.cast(self._callback_count, ctypes.c_void_p),
                    ctypes.c_uint64(begin), ctypes.c_uint64(end)
                )

        # save the ctype function so gc will leave it alone.
        self._ctype_cbs[self._callback_count] = cb

        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return _h2.value

    # delete a hook
    def hook_del(self, h):
        _h = uc_hook_h(h)
        status = _uc.uc_hook_del(self._uch, _h)
        if status != uc.UC_ERR_OK:
            raise UcError(status)
        h = 0

    def context_save(self):
        context = UcContext(self._uch)
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        return context

    def context_update(self, context):
        status = _uc.uc_context_save(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    def context_restore(self, context):
        status = _uc.uc_context_restore(self._uch, context.context)
        if status != uc.UC_ERR_OK:
            raise UcError(status)

    # this returns a generator of regions in the form (begin, end, perms)
    def mem_regions(self):
        regions = ctypes.POINTER(_uc_mem_region)()
        count = ctypes.c_uint32()
        status = _uc.uc_mem_regions(self._uch, ctypes.byref(regions), ctypes.byref(count))
        if status != uc.UC_ERR_OK:
            raise UcError(status)

        try:
            for i in range(count.value):
                yield (regions[i].begin, regions[i].end, regions[i].perms)
        finally:
            _uc.uc_free(regions)


class UcContext:
    def __init__(self, h):
        self._context = uc_context()
        self._size = _uc.uc_context_size(h)
        self._to_free = True
        status = _uc.uc_context_alloc(h, ctypes.byref(self._context))
        if status != uc.UC_ERR_OK:
            raise UcError(status)
    
    @property
    def context(self):
        return self._context

    @property
    def size(self):
        return self._size

    # Make UcContext picklable
    def __getstate__(self):
        return (bytes(self), self.size)
    
    def __setstate__(self, state):
        self._size = state[1]
        self._context = ctypes.cast(ctypes.create_string_buffer(state[0], self._size), uc_context)
        # __init__ won'e be invoked, so we are safe to set it here.
        self._to_free = False
        
    def __bytes__(self):
        return ctypes.string_at(self.context, self.size)

    def __del__(self):
        # We need this property since we shouldn't free it if the object is constructed from pickled bytes.
        if self._to_free:
            _uc.uc_context_free(self._context)


# print out debugging info
def debug():
    archs = {
        "arm": uc.UC_ARCH_ARM
    }

    all_archs = ""
    keys = archs.keys()
    for k in sorted(keys):
        if uc_arch_supported(archs[k]):
            all_archs += "-%s" % k

    major, minor, _combined = uc_version()

    return "python-%s-c%u.%u-b%u.%u" % (
        all_archs, major, minor, uc.UC_API_MAJOR, uc.UC_API_MINOR
    )
