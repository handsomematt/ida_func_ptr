import os

import idc
import idaapi
import idautils

import PySide.QtGui as QtGui
import PySide.QtCore as QtCore
QtWidgets = QtGui
QtCore.pyqtSignal = QtCore.Signal
QtCore.pyqtSlot = QtCore.Slot

#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

VERSION = "v1.0"
AUTHORS = ['Matt Stevens']

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return funcref_t()

class funcref_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    help = ""
    comment = "A plugin for easy function references"
    wanted_name = "funcref"
    wanted_hotkey = ""

    #--------------------------------------------------------------------------
    # Plugin Overloads
    #--------------------------------------------------------------------------

    def init(self):
        # just go when we have hexrays
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP

        # initialize the menu actions our plugin will inject
        self._init_action_bulk()
        self._init_action_copy()

        # initialize plugin hooks
        self._init_hooks()

        # done
        idaapi.msg("%s %s initialized...\n" % (self.wanted_name, VERSION))
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("%s cannot be run as a script.\n" % self.wanted_name)

    def term(self):
        if not hasattr(self, '_hooks'):
            return

        # unhook our plugin hooks
        self._hooks.unhook()

        # unregister our actions & free their resources
        self._del_action_bulk()
        self._del_action_copy()

        # done
        idaapi.msg("%s terminated...\n" % self.wanted_name)

    #--------------------------------------------------------------------------
    # Plugin Hooks
    #--------------------------------------------------------------------------

    def _init_hooks(self):
        self._hooks = Hooks()
        self._hooks.hook()

        if not idaapi.init_hexrays_plugin():
            idaapi.msg("[ERROR] Failed to initialize Hex-Rays SDK")
        else:
            idaapi.install_hexrays_callback(self._hooks.hxe_callback)

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_BULK = "funcref:bulk"
    ACTION_COPY = "funcref:copy"

    def _init_action_bulk(self):
        """
        Register the bulk prefix action with IDA.
        """

        icon_data = "".join([
                "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A\x00\x00\x00\x0D\x49\x48\x44\x52\x00\x00\x00\x10\x00\x00\x00\x10\x08\x06\x00\x00\x00\x1F\xF3\xFF\x61\x00\x00\x02\xCA\x49\x44\x41\x54\x78\x5E\x65",
                "\x53\x6D\x48\x53\x6F\x14\x3F\xBA\xB5\xB7\xA0\x8D\x20\x41\xF2\xBA\x5D\xB6\x0F\x56\xF4\x41\xA2\xC0\x9C\xE9\xB4\x29\x4A\x7D\xB0\x22\x7A\x11\x02\x23\x48\x2A\xD4\x74\x53\x33\x3F\xD4",
                "\x3E\x4A\x50\x19\xE4\xB0\xD0\x22\xCD\x44\x45\x4A\x31\x8C\x92\xA2\x3E\x65\x0A\x4D\xCB\x96\x7E\xE8\xD5\x97\xCC\xFE\xFE\x37\xA7\x77\xDB\xBD\xA7\xE7\x3C\xBE\x05\x9E\xED\xB7\xB3\xF3",
                "\x7B\x39\xF7\xEE\x19\x17\xA8\xAC\x56\xDB\x54\x82\x60\x41\xB3\x59\xBC\xFF\xAC\xF9\xCA\xB5\xAE\x86\xCA\xF9\x4E\xAF\x1B\x3B\xEA\x5D\x48\x9D\x66\xE2\x49\x27\x9F\xD5\x66\x9B\xA2\x1C",
                "\x22\x02\xD0\x40\xE4\x81\x6C\x3B\x76\x37\x56\xE3\x37\x5F\x2F\x62\xE8\x0B\xD3\x66\x19\x7E\x53\xA7\x99\x78\xAE\x1F\x64\x3E\x21\x71\x69\x09\x5F\x20\x98\x2D\x58\x70\x24\x07\x07\x7B",
                "\x6F\xB0\x79\x82\x61\x81\x21\xCC\xDE\x21\x54\x16\x02\xD4\x69\x26\x9E\x74\xEE\xCB\xCF\x4D\xC7\x44\xB3\x88\x7C\x81\xC5\x22\xFE\x6C\xB9\xE9\x46\x67\x46\x1A\x8A\x16\x2B\x0A\x5B\x05",
                "\x74\x66\x65\xE1\x98\x6F\x00\x31\x32\x87\x9F\x59\x77\x66\x66\x61\x42\xBC\xC0\xF5\x6C\x47\x1A\x36\xD7\xB9\x51\x14\xC5\x1E\xBE\xA0\xC3\x5B\xD9\x98\x99\xE1\xC0\xCE\xBE\x57\x48\xD7",
                "\x9A\x63\x68\xEA\x7C\x8A\xF6\x14\x3B\x9F\xF6\xA6\xA4\x60\xEB\xE3\x3E\x9C\x5F\xD6\x5A\x7A\xFA\x71\xBF\xC3\x81\x3D\x4D\x35\x0D\x7C\xC1\xF3\x87\x57\x43\xF9\x87\x8F\x21\x95\x5E\xAB",
                "\x41\x83\x4E\x83\x54\xDB\x92\x76\x20\xCA\xBF\xD0\x99\x9D\xBB\x4E\xDB\xBD\xC7\x8E\x2F\x5A\x3D\x74\x3D\x50\x03\x80\x7E\x7A\x7A\x06\x46\x47\xFD\xA0\x33\x6C\x84\x18\x46\x0C\xBD\x1F",
                "\x86\x2D\x71\x71\x00\x52\x10\x16\x17\xE6\xC1\xE7\x1B\x61\x9A\x81\x69\x31\x30\xFC\x61\x14\xB4\x3A\x3D\x20\x82\x1E\x58\xA9\x15\x05\x41\x14\x05\xB8\x58\xEE\x82\x7D\xE9\x99\x20\xCB",
                "\x32\x94\x95\x95\xC3\xA5\xD2\x53\x00\x51\x09\xAA\x4B\x0B\xA1\xB8\xA4\x0C\x52\x53\x33\x40\xA5\x52\x81\xDB\x5D\x01\xA2\x45\x00\x45\x51\x80\x2A\x36\x12\x8D\x42\x49\x51\x01\x44\xE5",
                "\x18\x90\x22\x0A\x98\x8C\x46\xF0\x54\x14\x42\x6D\x7D\x3B\xE4\x1C\x75\x41\xAD\xB7\x1D\x3C\x55\x85\x60\x32\x19\x41\x8A\x2A\xDC\x57\x5C\x74\x12\x28\x47\xA5\x8E\x44\xE4\xF0\x76\x5B",
                "\x82\xA6\xCD\x5B\x0D\xB2\x12\xE6\xE4\x06\xB5\x1A\x66\xA7\x26\x41\x92\xC2\xA0\xD5\x6A\x60\x67\x92\x19\xAE\x7B\xCE\x70\x4D\x15\xAB\x01\xAD\xC1\x08\x3F\x46\x64\x6E\x8E\x9D\xF9\x13",
                "\xE8\x1A\xFF\xE4\x63\x8A\x0E\xE6\x02\x41\xF8\x3F\x18\x82\x40\x28\x04\xFD\xDD\x75\xF0\xB6\xFF\x2E\x75\x9A\x89\x27\x9D\xFB\xC8\x4F\x39\xBE\xE0\xB4\xAB\xCE\x35\xFE\x71\x00\x16\x17",
                "\x25\x76\x50\x26\x76\x6B\x61\x86\x08\xE4\x1D\xAF\x81\xBC\x13\x97\xA9\xD3\x4C\x3C\xE9\xDC\x47\x7E\xCA\xF1\x05\x0C\x5F\x7D\xFE\xEF\x35\x03\xAF\x9F\x00\xB0\x73\x30\x9A\xE2\x81\x0E",
                "\xF6\xC1\xED\x52\xB8\x77\xAB\x98\x3A\xCD\xC4\x73\x9D\x7C\x6F\xDE\xF9\xCF\x53\x0E\xFE\xA9\xCD\xAE\xB3\x87\xCE\x75\x35\x54\xE1\xD0\xCB\x47\x38\x39\x36\x88\xFF\x4D\xF8\x57\x41\x33",
                "\xF1\xA4\x93\x0F\x00\x36\xAD\x3E\x4C\x6B\xC5\xC9\x5D\x77\x6A\x2F\xB4\x31\xA3\xC4\x40\x4F\x21\x0F\xD1\x4C\x3C\xE9\x2B\xE1\xF5\x0B\xD6\x90\xC8\x90\x4C\xE6\x35\xD0\xCC\x79\x5E\xFF",
                "\x2E\xF8\x0B\x2F\x3D\xE5\xC3\x97\x06\xCF\xCF\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82"])

        # load the icon for this action
        self._bulk_icon_id = idaapi.load_custom_icon(data=icon_data, format="png")

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_BULK,                                        # The action name.
            "Copy function pointers to selected function(s)",        # The action text.
            IDACtxEntry(bulk_function),                              # The action handler.
            None,                                                    # Optional: action shortcut
            "Copies a function pointer to the selected function(s)", # Optional: tooltip
            self._bulk_icon_id                                       # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"


    def _init_action_copy(self):
        # load the icon for this action
        self._copy_icon_id = 199

        # describe the action
        action_desc = idaapi.action_desc_t(
            self.ACTION_COPY,                  # The action name.
            "Copy function reference",         # The action text.
            IDACtxEntry(copy_function_cursor), # The action handler.
            None,                              # Optional: action shortcut
            "Copy reference of this function", # Optional: tooltip
            self._copy_icon_id                 # Optional: the action icon
        )

        # register the action with IDA
        assert idaapi.register_action(action_desc), "Action registration failed"

    def _del_action_bulk(self):
        idaapi.unregister_action(self.ACTION_BULK)
        idaapi.free_custom_icon(self._bulk_icon_id)
        self._bulk_icon_id = idaapi.BADADDR

    def _del_action_copy(self):
        idaapi.unregister_action(self.ACTION_COPY)
        #idaapi.free_custom_icon(self._copy_icon_id)
        self._copy_icon_id = idaapi.BADADDR

#------------------------------------------------------------------------------
# Plugin Hooks
#------------------------------------------------------------------------------

class Hooks(idaapi.UI_Hooks):

    def finish_populating_tform_popup(self, form, popup):
        # disassembly window
        if idaapi.get_tform_type(form) == idaapi.BWN_DISASMS:
            if get_cursor_func_ref() == idaapi.BADADDR:
                return

            idaapi.attach_action_to_popup(
                form,
                popup,
                funcref_t.ACTION_COPY
            )

        # functions window
        elif idaapi.get_tform_type(form) == idaapi.BWN_FUNCS:
            idaapi.attach_action_to_popup(form, popup, funcref_t.ACTION_BULK, "Copy All", idaapi.SETMENU_INS)

        return 0

    def hxe_callback(self, event, *args):
        if event == idaapi.hxe_populating_popup:
            form, popup, vu = args

            if get_cursor_func_ref() == idaapi.BADADDR:
                return 0

            idaapi.attach_action_to_popup(
                form,
                popup,
                funcref_t.ACTION_COPY,
                "Rename global item",
                idaapi.SETMENU_APP
            )

        return 0


def copy_to_clip(data):
    QtGui.QApplication.clipboard().setText(data)

def copy_function_cursor():
    # get the function reference under the user cursor (if there is one)
    target = get_cursor_func_ref()
    if target == idaapi.BADADDR:
        return

    # execute the recursive prefix
    functionPtrDef = copy_function(target)
    copy_to_clip(functionPtrDef)
    idaapi.msg(functionPtrDef + "\n")

def copy_function(addr):

    func_addr = idc.LocByName(idaapi.get_func_name(addr))
    if func_addr == idaapi.BADADDR:
        idaapi.msg("0x%08X does not belong to a defined function\n" % addr)
        return

    callTypes = ["__cdecl", "__fastcall", "__stdcall", "__thiscall", "__usercall"]

    funcDef = str(idaapi.decompile(func_addr)).split('\n', 1)[0]

    hasCallType = any(call_type in funcDef for call_type in callTypes)
    parenthesesStart = funcDef.find('(')
    parenthesesEnd = funcDef.rfind(')')
    funcNameStart = funcDef[0 : parenthesesStart].rfind(' ')
    funcNameEnd = parenthesesStart
    returnTypeStart = 0
    returnTypeEnd = funcNameStart

    callType = ""
    if hasCallType:
        callTypeStart = funcDef[0 : funcNameStart].rfind(' ')
        callType = funcDef[callTypeStart + 1 : funcNameStart]
        returnTypeEnd = callTypeStart
        if callType == "__cdecl":
            callType = ""

    returnType = funcDef[returnTypeStart : returnTypeEnd]
    funcName = funcDef[funcNameStart + 1 : parenthesesStart]
    args = funcDef[parenthesesStart + 1 : parenthesesEnd]

    finalString = "{0} ({1}* {2})({3}) = ({0}({1}*)({3}))({4});".format(
        returnType, callType, funcName, args, "0x%08X" % func_addr
    )

    return finalString

def bulk_function():
    functionPtrs = ""
    for func_name in get_selected_funcs():
        functionPtrDef = copy_function(idc.LocByName(func_name))
        functionPtrs = functionPtrs + functionPtrDef + "\n"
    copy_to_clip(functionPtrs)
    idaapi.msg(functionPtrs)

def get_all_funcs():
    return set(idaapi.get_func_name(ea) for ea in idautils.Functions())

def get_cursor_func_ref():
    current_tform  = idaapi.get_current_tform()
    tform_type     = idaapi.get_tform_type(current_tform)

    # get the hexrays vdui (if available)
    vu = idaapi.get_tform_vdui(current_tform)
    if vu:
        cursor_addr = vu.item.get_ea()
    elif tform_type == idaapi.BWN_DISASM:
        cursor_addr = idaapi.get_screen_ea()

        op_addr = idc.GetOperandValue(cursor_addr, idaapi.get_opnum())
        op_func = idaapi.get_func(op_addr)
        if op_func and op_func.startEA == op_addr:
            return op_addr

    else:
        return idaapi.BADADDR

    cursor_func = idaapi.get_func(cursor_addr)
    if cursor_func and cursor_func.startEA == cursor_addr:
        return cursor_addr

    return idaapi.BADADDR

def get_selected_funcs():
    tform = idaapi.find_tform("Functions window")
    if not tform:
        idc.Warning("Unable to find 'Functions window'")
        return

    widget = idaapi.PluginForm.FormToPySideWidget(tform)
    table = widget.findChild(QtWidgets.QTableView)
    selected_funcs = [str(s.data()) for s in table.selectionModel().selectedRows()]

    return match_funcs(selected_funcs)

def match_funcs(qt_funcs):
    res = set()
    ida_funcs = get_all_funcs()
    for f in qt_funcs:
        for f2 in ida_funcs:
            if len(f) == len(f2):
                i = 0
                while i < len(f) and (f[i] == f2[i] or f[i] == '_'):
                    i += 1

                if i == len(f):
                    res.add(f2)
                    break

    return list(res)

def graph_down(ea, path=set()):
    """
    Recursively collect all function calls.

    Copied with minor modifications from
    http://hooked-on-mnemonics.blogspot.com/2012/07/renaming-subroutine-blocks-and.html
    """
    path.add(ea)

    #
    # iterate through all the instructions in the target function (ea) and
    # inspect all the call instructions
    #

    for x in [x for x in idautils.FuncItems(ea) if idaapi.is_call_insn(x)]:

        #  TODO
        for r in idautils.XrefsFrom(x, idaapi.XREF_FAR):
            #print "0x%08X" % h, "--calls-->", "0x%08X" % r.to
            if not r.iscode:
                    continue

            # get the function pointed at by this call
            func = idaapi.get_func(r.to)
            if not func:
                continue

            # ignore calls to imports / library calls / thunks
            if (func.flags & (idaapi.FUNC_THUNK | idaapi.FUNC_LIB)) != 0:
                continue

            #
            # if we have not traversed to the destination function that this
            # call references, recurse down to it to continue our traversal
            #

            if r.to not in path:
                graph_down(r.to, path)

    return path

class IDACtxEntry(idaapi.action_handler_t):
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
