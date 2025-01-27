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
logger.setLevel(logging.INFO)
if not logger.hasHandlers():
    logger.addHandler(logging.StreamHandler())

def pure_patch(ea: int, patch: bytes) -> None:
    logger.info(f"patching {binascii.hexlify(patch)} at {ea:X}")
    match ida_ida.inf_get_filetype():
        case ida_ida.f_COFF | ida_ida.f_PE:
            filetype = binmodify.FileType.Coff
        case ida_ida.f_ELF:
            filetype = binmodify.FileType.Elf
        case _:
            raise Exception(f"File type not supported {ida_ida.inf_get_filetype()}")

    with binmodify.ZigStream(ida_nalt.get_input_file_path().encode()) as zs, binmodify.HackStream(zs) as hs, binmodify.HackPatcher(hs, filetype) as hp:
        hp.pure_patch(ea, patch, hs)
        old = hp.get_old_addr()
        new = hp.get_new_addr()
        is_end = hp.get_is_end()
        if is_end:
            ida_segment.set_segm_end(old, new, 0)
        else:
            ida_segment.set_segm_start(old, new, 0)
        temp = hs.get_next_write_record()
        while temp is not None:
            pos, bts = temp
            addr = hp.off_to_addr(pos)
            ida_bytes.put_bytes(addr, bts)
            temp = hs.get_next_write_record()
        func = ida_funcs.get_func(ea)
        if is_end:
            ida_funcs.append_func_tail(func, old, new)
        else:
            ida_funcs.append_func_tail(func, new, old)

# def create_cave(size: int) -> None:
#     logger.info(f"Creating cave of size {size:X}")

class InlineHookActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        patch = ida_kernwin.ask_str("", 0, "Bytes to insert")
        if patch is not None:
            ea = idc.get_screen_ea()
            pure_patch(ea, binascii.unhexlify(patch))
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
    flags = ida_idaapi.PLUGIN_MULTI
    comment = "Patch assembly with ease"
    help = "Insert inline hook, and create code caves"
    wanted_name = "Binmodify"

    def init(self):
        if not ida_kernwin.register_action(inline_hook_act_desc): logger.warning("failed to register inline hook action")
        self.hooks = Hooks()
        self.hooks.hook()

    def deinit(self):
        self.hooks.unhook()


def PLUGIN_ENTRY():
    return binmodify_plugin_t()
