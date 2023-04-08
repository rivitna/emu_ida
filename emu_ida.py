"""
Code emulator plugin for IDA Pro

https://github.com/rivitna/emu_ida

The plugin is designed for simple data decryption and getting stack strings.

Special thanks @herrcore for IDAPython plugin template.
"""

import io
import os
import errno
import binascii
from unicorn import *
from unicorn.x86_const import *
import idautils
import idaapi
import ida_kernwin
import ida_ida
import ida_nalt
import ida_segment
import ida_bytes
import ida_ua
import ida_allins
import ida_lines


#****************************************************************************
__AUTHOR__ = '@rivitna'
#****************************************************************************
PLUGIN_NAME = 'Emu'
VERSION = '0.0.7'
PLUGIN_HOTKEY = 'Alt+E'
#****************************************************************************


# Debug
DEBUG = False

# Dump data
DUMP_DATA = True
DUMP_DIR_PATH = './emu_dumps/'


# Comments
COMMENT_DATA_MAX_LEN = 256


# Stack
STACK_SIZE = 0x100000
ESP_INIT_POS = (STACK_SIZE // 2) & ~0xFF
EBP_INIT_POS = (3 * STACK_SIZE // 4) & ~0xFF

# Dummy block (block for zero addresses)
DUMMY_BLOCK_SIZE = 0x100000


# Skipped instructions that are written to memory
SKIP_WRITE_MEM_INSTRUCTIONS = frozenset([
    ida_allins.NN_call,
    ida_allins.NN_callfi,
    ida_allins.NN_callni,
    ida_allins.NN_enterw,
    ida_allins.NN_enter,
    ida_allins.NN_enterd,
    ida_allins.NN_enterq,
    ida_allins.NN_pushaw,
    ida_allins.NN_pusha,
    ida_allins.NN_pushad,
    ida_allins.NN_pushaq,
    ida_allins.NN_pushfw,
    ida_allins.NN_pushf,
    ida_allins.NN_pushfd,
    ida_allins.NN_pushfq,
    ])


class EmuError(Exception):
    """Plugin Error class."""
    pass


#****************************************************************************
# Global settings
#****************************************************************************

def global_settings():

    print('Emu: Configuration.')


#****************************************************************************
# Code emulate
#****************************************************************************

def data_to_text(data):
    """Convert data to text."""

    if (len(data) == 0):
        return ''

    prefix = ''

    data_len = len(data)

    try:
        if (data_len < 2) or (data_len & 1) or (data[1] != 0):
            s = data.decode()
        else:
            s = data.decode('UTF-16-LE')
            prefix = 'L'

        s = s.strip('\0')
        s = s.encode('unicode_escape').decode().replace('\"', '\\"')
        text = prefix + '\"' + s + '\"'

    except UnicodeDecodeError:
        text = ''

    finally:
        ln = min(COMMENT_DATA_MAX_LEN, data_len)
        for block in (data[i : i + 16] for i in range(0, ln, 16)):
            if (text != ''):
                text += '\n'
            text += binascii.hexlify(block, ' ', 1).decode()
        if ln < data_len:
            text += '\n... (%d bytes)' % (data_len - ln)

    return text


def trace_log(text):
    """Trace log."""
    with io.open('emutrace.log', 'a') as f:
        f.write(text + '\n')


def mkdirs(dir):
    """Make directories."""
    try:
        os.makedirs(dir)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def dump_data(code_start_ea, code_end_ea, index, data_ea, data_size, data):
    """Dump data."""
    dump_dir_path = (DUMP_DIR_PATH +
                     '%08X_%08X/' % (code_start_ea, code_end_ea))
    mkdirs(dump_dir_path)
    dump_path = (dump_dir_path +
                 '%02d_%08X_%08x.bin' % (index, data_ea, data_size))
    with io.open(dump_path, 'wb') as f:
        f.write(data)


def hook_mem_write(uc, access, address, size, value, data_entries):
    """Callback for memory write."""

    is_64bit = (uc._mode == UC_MODE_64)

    eip = uc.reg_read(UC_X86_REG_RIP if is_64bit else UC_X86_REG_EIP)

    do_skip = False

    # Decode instruction
    insn = ida_ua.insn_t()
    inslen = ida_ua.decode_insn(insn, eip)
    if (inslen > 0):
        # Skip instruction?
        if (insn.itype in SKIP_WRITE_MEM_INSTRUCTIONS):
            do_skip = True

    if DEBUG:
        # Debug: trace log
        disasm_text = ida_lines.generate_disasm_line(eip, 0)
        if disasm_text:
            disasm_text = ida_lines.tag_remove(disasm_text)
        addr_fmt_str = '%016X' if is_64bit else '%08X'
        val_fmt_str = '%0' + str(2 * size) + 'X'
        log_fmt_str = addr_fmt_str + '\t%s\t' + \
                      val_fmt_str + ' (%d) -> ' + addr_fmt_str
        log_str = log_fmt_str % (eip, disasm_text, value, size, address)
        log_str += '\t' + ('Skipped' if do_skip else 'Processed')
        trace_log(log_str)

    if do_skip:
        return

    start = address
    end = start + size

    for i, data_entry in reversed(list(enumerate(data_entries))):

        data_start = data_entry[0]
        data_end = data_start + data_entry[1]

        if ((data_start <= start <= data_end) or
            (data_start <= end <= data_end)):
            start = min(data_start, start)
            end = max(data_end, end)
            new_entry = (start, end - start)
            if (i < len(data_entries) - 1):
                del data_entries[i]
                data_entries.append(new_entry)
            else:
                data_entries[i] = new_entry
            break

    else:
        data_entries.append((address, size))


def code_emulate():
    """Emulate highlighted code."""

    # Get highlighted range
    selection, start_ea, end_ea = ida_kernwin.read_range_selection(None)

    if not selection:
        ea = ida_kernwin.get_screen_ea()
        start_ea = idaapi.get_item_head(ea)
        end_ea = idaapi.get_item_end(ea)

    print('Emu: Start code emulation...')
    print('Emu: Start address: %08X' % start_ea)
    print('Emu: End address: %08X' % end_ea)

    image_base = ida_nalt.get_imagebase()
    mode = UC_MODE_64 if ida_ida.inf_is_64bit() else UC_MODE_32
    image_size = ida_ida.inf_get_max_ea() - image_base
    image_size = (image_size + 0xFFFF) & ~0xFFFF

    dummy_size = min(DUMMY_BLOCK_SIZE, image_base)
    stack_addr = (dummy_size + 0xFFFF) & ~0xFFFF
    if (stack_addr + STACK_SIZE > image_base):
        stack_addr = (image_base + image_size + 0xFFFF) & ~0xFFFF

    try:

        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)

        # Map memory for this emulation
        # Dummy block
        dummy_size = min(DUMMY_BLOCK_SIZE, image_base)
        if dummy_size != 0:
            mu.mem_map(0, dummy_size)
        # Image
        mu.mem_map(image_base, image_size)
        # Stack
        mu.mem_map(stack_addr, STACK_SIZE)

        for n in range(ida_segment.get_segm_qty()):

            seg = ida_segment.getnseg(n)
            if seg and (seg.end_ea > seg.start_ea):
                seg_data = ida_bytes.get_bytes(seg.start_ea,
                                               seg.end_ea - seg.start_ea)

                # Write section data to memory
                mu.mem_write(seg.start_ea, seg_data)

        # Initialize emulator
        if mode == UC_MODE_64:
            esp_id = UC_X86_REG_RSP
            ebp_id = UC_X86_REG_RBP
        else:
            esp_id = UC_X86_REG_ESP
            ebp_id = UC_X86_REG_EBP
        mu.reg_write(esp_id, stack_addr + ESP_INIT_POS)
        mu.reg_write(ebp_id, stack_addr + EBP_INIT_POS)

        data_entries = []

        mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write, data_entries)

        # Emulate machine code in infinite time
        mu.emu_start(start_ea, end_ea)

        if (len(data_entries) >= 1):

            # Select result data entry
            if (len(data_entries) == 1):

                res_data_entry = data_entries[0]

            else:

                res_data_entry = None
                stack_data_entry = None

                for data_entry in data_entries:
                    addr = data_entry[0]

                    # Stack?
                    if (stack_addr <= addr < stack_addr + STACK_SIZE):
                        if ((stack_data_entry is None) or
                            (addr >= stack_data_entry[0])):
                            stack_data_entry = data_entry
                            res_data_entry = data_entry

                    # Image?
                    elif (image_base <= addr < image_base + image_size):
                        res_data_entry = data_entry

                    # Dummy block?
                    elif (addr < DUMMY_BLOCK_SIZE):
                        res_data_entry = data_entry

                if res_data_entry is None:
                    res_data_entry = data_entries[-1]

            res_data = mu.mem_read(*res_data_entry)
            ida_bytes.set_cmt(start_ea, data_to_text(res_data), 1)

            if DUMP_DATA:
                # Save data blocks to files
                for i, data_entry in enumerate(data_entries):
                    # Dump data
                    dump_data(start_ea, end_ea, i,
                              data_entry[0], data_entry[1],
                              mu.mem_read(*data_entry))

        print('Emu: Code emulation done.')

    except UcError as e:

        print('Emu Error: %s' % e)


#****************************************************************************
# Plugin
#****************************************************************************
class EmuPlugin(idaapi.plugin_t):
    """
    IDA Plugin for code emulation.
    """

    comment = 'IDA code emulator'
    help = ''
    wanted_name = PLUGIN_NAME
    # We only want a hotkey for the actual hash lookup
    wanted_hotkey = ''
    flags = idaapi.PLUGIN_KEEP

    def init(self):
        """
        This is called by IDA when it is loading the plugin.
        """

        global g_initialized

        # Check if already initialized 
        if not g_initialized:
            g_initialized = True

            # Print header
            print('IDA code emulator v%s by rivitna.' % VERSION)

            # Initialize the menu actions our plugin will inject
            self._init_action_code_emulate()

            self._init_hooks()
            return idaapi.PLUGIN_KEEP


    def run(self, arg):
        """
        This is called by IDA when the plugin is run from the plugins menu.
        """
        global_settings()


    def term(self):
        """
        This is called by IDA when it is unloading the plugin.
        """
        pass


    #
    # IDA Actions
    #
    ACTION_CODE_EMULATE  = 'emu:code_emulate'

    def _init_action_code_emulate(self):
        """
        Register the code emulation action with IDA.
        """
        action_desc = idaapi.action_desc_t(self.ACTION_CODE_EMULATE,
                                           'Code emulate',
                                           EmuActionHandler(code_emulate),
                                           PLUGIN_HOTKEY,
                                           'Code emulation')
        # Register the action with IDA
        res = idaapi.register_action(action_desc)
        assert res, 'Action registration failed'


    def _init_hooks(self):
        """
        Install plugin hooks into IDA.
        """
        self._hooks = EmuHooks()
        self._hooks.hook()


#****************************************************************************
# Plugin Hooks
#****************************************************************************
class EmuHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0


#****************************************************************************
# Prefix Wrappers
#****************************************************************************
def inject_actions(form, popup, form_type):
    """
    Inject actions to popup menu(s) based on context.
    """

    # Disassembly window
    if (form_type == idaapi.BWN_DISASMS):

        # Insert the action entry into the menu

        idaapi.attach_action_to_popup(form,
                                      popup,
                                      EmuPlugin.ACTION_CODE_EMULATE,
                                      'Code emulate',
                                      idaapi.SETMENU_APP)

    return 0


#****************************************************************************
# Plugin Action Handler
#****************************************************************************
class EmuActionHandler(idaapi.action_handler_t):
    """
    A basic Context Menu class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        idaapi.action_handler_t.__init__(self)
        self.action_function = action_function

    def activate(self, ctx):
        """
        Execute the embedded action_function when this context menu is invoked.
        """
        self.action_function()
        return 1

    def update(self, ctx):
        """
        Ensure the context menu is always available in IDA.
        """
        return idaapi.AST_ENABLE_ALWAYS


#****************************************************************************
# Plugin Registration
#****************************************************************************

# Global flag to ensure plugin is only initialized once
g_initialized = False

# Register IDA plugin
def PLUGIN_ENTRY():
    return EmuPlugin()
