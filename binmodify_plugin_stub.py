from binmodify import binmodify

import binascii

import idc
import ida_ida
import ida_nalt
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_segment
import ida_kernwin

import logging

logger = logging.getLogger("binmodify")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    logger.addHandler(logging.StreamHandler())

def pure_patch(ea: int, patch: bytes, filetype: binmodify.FileType) -> None:
    logger.debug(f"patching {binascii.hexlify(patch)} at {ea:X}")
    with binmodify.ZigStream(ida_nalt.get_input_file_path().encode()) as zs, binmodify.HackStream(zs) as hs, binmodify.HackPatcher(hs, filetype) as hp:
        hp.pure_patch(ea, patch, hs)
        old = hp.get_old_addr()
        new = hp.get_new_addr()
        is_end = hp.get_is_end()
        if is_end:
            # plus one since this can only return a possible address while in case of an end cave we need one past the last possible address.
            new += 1
            logger.debug(f"adjusting segm end from {old:X} to {new:X}")
            # negative one because ida wants an ea that is inside of the segment.
            ida_segment.set_segm_end(old, new, 0)
        else:
            logger.debug(f"adjusting segm start from {old:X} to {new:X}")
            ida_segment.set_segm_start(old, new, 0)
        temp = hs.get_next_write_record()
        while temp is not None:
            pos, bts = temp
            addr = hp.off_to_addr(pos)
            logger.debug(f"writing bytes {binascii.hexlify(bts)} at addr {addr:X}")
            ida_bytes.put_bytes(addr, bts)
            temp = hs.get_next_write_record()
        func = ida_funcs.get_func(ea)
        if is_end:
            logger.debug(f"appending func tail {old:X} - {new:X}")
            ida_funcs.append_func_tail(func, old, new)
        else:
            logger.debug(f"appending func tail {new:X} - {old:X}")
            ida_funcs.append_func_tail(func, new, old)


def filetype_str(filetype: "filetype_t") -> str:
    match filetype:
        case ida_ida.f_EXE_old: return "f_EXE_old"
        case ida_ida.f_COM_old: return "f_COM_old"
        case ida_ida.f_BIN: return "f_BIN"
        case ida_ida.f_DRV: return "f_DRV"
        case ida_ida.f_WIN: return "f_WIN"
        case ida_ida.f_HEX: return "f_HEX"
        case ida_ida.f_MEX: return "f_MEX"
        case ida_ida.f_LX: return "f_LX"
        case ida_ida.f_LE: return "f_LE"
        case ida_ida.f_NLM: return "f_NLM"
        case ida_ida.f_COFF: return "f_COFF"
        case ida_ida.f_PE: return "f_PE"
        case ida_ida.f_OMF: return "f_OMF"
        case ida_ida.f_SREC: return "f_SREC"
        case ida_ida.f_ZIP: return "f_ZIP"
        case ida_ida.f_OMFLIB: return "f_OMFLIB"
        case ida_ida.f_AR: return "f_AR"
        case ida_ida.f_LOADER: return "f_LOADER"
        case ida_ida.f_ELF: return "f_ELF"
        case ida_ida.f_W32RUN: return "f_W32RUN"
        case ida_ida.f_AOUT: return "f_AOUT"
        case ida_ida.f_PRC: return "f_PRC"
        case ida_ida.f_EXE: return "f_EXE"
        case ida_ida.f_COM: return "f_COM"
        case ida_ida.f_AIXAR: return "f_AIXAR"
        case ida_ida.f_MACHO: return "f_MACHO"
        case ida_ida.f_PSXOBJ: return "f_PSXOBJ"
        case ida_ida.f_MD1IMG: return "f_MD1IMG"
        case _: return "Unknown"

filetype = None
def get_filetype() -> binmodify.FileType:
    global filetype
    if filetype is None:
        temp = ida_ida.inf_get_filetype()
        match temp:
            case ida_ida.f_COFF | ida_ida.f_PE:
                filetype = binmodify.FileType.Coff
            case ida_ida.f_ELF:
                filetype = binmodify.FileType.Elf
            case _:
                raise Exception(f"File type not supported {filetype_str(temp)}")
    return filetype

# def create_cave(size: int) -> None:
#     logger.info(f"Creating cave of size {size:X}")

class InlineHookActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        patch = ida_kernwin.ask_str("", 0, "Bytes to insert")
        if patch is not None:
            ea = idc.get_screen_ea()
            pure_patch(ea, binascii.unhexlify(patch), get_filetype())
        return 1

    def update(self, ctx):
        if (ctx.widget) and (ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM):
            return ida_kernwin.AST_ENABLE_ALWAYS
        return ida_kernwin.AST_DISABLE


# class CreateCaveActionHandler(ida_kernwin.action_handler_t):
#     def activate(self, ctx):
#         patch = ida_kernwin.ask_long(None, "Cave size")
#         if patch is not None:
#             ea = idc.get_screen_ea()
#             pure_patch(ea, binascii.unhexlify(patch))
#         return 1
#
#     def update(self, ctx):
#         if (ctx.widget) and (ida_kernwin.get_widget_type(ctx.widget) == ida_kernwin.BWN_DISASM):
#             return ida_kernwin.AST_ENABLE_ALWAYS
#         return ida_kernwin.AST_DISABLE
#

# create_cave_act_desc = ida_kernwin.action_desc_t(
#     name="binmodify:create_cave",
#     "Add code cave",
#     InlineHookActionHandler(),
#     "Shift+I",
#     "Insert an inline hook which jumps to provided code and then returns",
# )
# if not ida_kernwin.register_action(inline_hook_act_desc): logger.warning("failed to register inline hook action")

inline_hook_act_name = "binmodify:inline_hook"

inline_hook_act_desc = ida_kernwin.action_desc_t(
    inline_hook_act_name,
    "Add inline hook",
    InlineHookActionHandler(),
    "Shift+I",
    "Insert an inline hook which jumps to provided code and then returns",
)


class Hooks(ida_kernwin.UI_Hooks):
    def populating_widget_popup(self, widget, popup):
        # You can attach here.
        pass
    def finish_populating_widget_popup(self, widget, popup):
        # Or here, after the popup is done being populated by its owner.
        # We will attach our action to the context menu
        # for the 'Functions window' widget.
        # The action will be be inserted in a submenu of
        # the context menu, named 'Others'.
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup, inline_hook_act_name, "Binmodify/")


class binmodify_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_HIDE
    comment = "Patch assembly with ease"
    help = "Insert inline hook, and create code caves"
    wanted_name = "Binmodify"

    def init(self):
        try:
            get_filetype()
        except Exception as e:
            logger.warning(e.args[0])
            return ida_idaapi.PLUGIN_SKIP
        if not ida_kernwin.register_action(inline_hook_act_desc): logger.warning("failed to register inline hook action")
        self.hooks = Hooks()
        self.hooks.hook()
        return ida_idaapi.PLUGIN_OK

    def term(self):
        self.hooks.unhook()


def PLUGIN_ENTRY():
    return binmodify_plugin_t()
