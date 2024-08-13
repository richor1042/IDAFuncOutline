import idautils
import ida_name
import ida_funcs
import idaapi
import idc
import re

ins_num_limit=5
arm64_ins_space=4
def set_outline_func_flag(func_addr):
    pfn = ida_funcs.get_func(func_addr)
    pfn.flags |= idaapi.FUNC_OUTLINE
    ida_funcs.update_func(pfn)

def check_func(func_addr):
    start_ea = idc.get_func_attr(func_addr, idc.FUNCATTR_START)
    end_ea = idc.get_func_attr(func_addr, idc.FUNCATTR_END)
    # Limit number of instructions
    if end_ea-start_ea>ins_num_limit*arm64_ins_space:
        return False
    #Limit the last instruction
    ins = idc.GetDisasm(end_ea-arm64_ins_space)
    opt_code = ins.split("             ")
    if opt_code[0]!="B":
        return False
    return True

def visit_func(blk):
    pat = "_[0-9a-fA-f]+"
    curr_addr = blk.start_ea
    while curr_addr < blk.end_ea:
        ins=idc.GetDisasm(curr_addr)
        opt_code = ins.split("             ")

        if len(opt_code)==2:
            if ((opt_code[0].find("BL")==0)and(opt_code[0]!="BLR")) and (opt_code[1].replace(" ","").find("_")!=0):
                pat = "_[0-9a-fA-f]+"
                tmpcont=re.findall(pat,opt_code[1])
                func_son_addr=tmpcont[0][1:]
                if check_func(int(func_son_addr,16)):
                    # print("set_outline_func_flag", func_son_addr)
                    set_outline_func_flag(int(func_son_addr,16))

        curr_addr = idc.next_head(curr_addr, blk.end_ea)

def outline_resume(fn_addr):
    print("Extract Resume",hex(fn_addr))
    f_blocks = idaapi.FlowChart(ida_funcs.get_func(fn_addr))
    for block in f_blocks:
        visit_func(block)
    ida_funcs.update_func(fn_addr)
    print("Extract Resume finish",hex(fn_addr))


PSEUDOCODE_CLICK = "PSEUDOCODEClick"
MENU_PATH = "FuncOutlineUI/"

class FuncOutlineUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        if idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(widget, popup, PSEUDOCODE_CLICK, MENU_PATH)

class FuncOutlineUIActions(idaapi.action_handler_t):
    def __init__(self, name):
        idaapi.action_handler_t.__init__(self)
        self.name = name

    def activate(self, ctx):
        if self.name == PSEUDOCODE_CLICK:
            ea = idc.here()
            now_func = ida_funcs.get_func(ea)
            outline_resume(now_func.start_ea)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class FuncOutlineUI(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "funcOutline UI Plugin"
    help = "This is a funcOutline UI plugin"
    wanted_name = "funcOutline UI Plugin"
    wanted_hotkey = ""
    def init(self):
        self.hooks = FuncOutlineUIHooks()
        self.hooks.hook()


        # Register action for PSEUDOCODEClick
        action_desc = idaapi.action_desc_t(
            PSEUDOCODE_CLICK,
            "FuncOutline resume",
            FuncOutlineUIActions(PSEUDOCODE_CLICK),
            '',
            "FuncOutline resume",
            50)
        idaapi.register_action(action_desc)

        return idaapi.PLUGIN_KEEP

    def term(self):
        self.hooks.unhook()
        idaapi.unregister_action(PSEUDOCODE_CLICK)
    def run(self, arg):
        pass

def PLUGIN_ENTRY():
    return FuncOutlineUI()