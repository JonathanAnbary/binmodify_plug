#include "plugin.h"

#define ACTION_NAME "binmodify:InlineHook"
#define ACTION_LABEL "Add inline hook"

 int idaapi inline_hook_ah_t::activate(action_activation_ctx_t *) {
    qstring patch;
    if (!ask_str(&patch, 0, "Bytes to insert")) {
      return false;
    }
    pure_patch(ctx.patch_ctx, get_screen_ea(), patch.c_str(), patch.size());
  }

action_state_t idaapi inline_hook_ah_t::update(action_update_ctx_t * update_ctx) {
    if ((update_ctx) && (update_ctx->widget_type == BWN_DISASM))
      return AST_ENABLE_ALWAYS;
    return AST_DISABLE;
  }

#define MAX_PATH_SIZE 100

plugin_ctx_t::plugin_ctx_t(Filetype ftype)
  : inline_hook_act(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        ACTION_LABEL,
        &inline_hook_ah,
        this,
        "Shift+I",
        "Insert an inline hook which jumps to provided code and then returns", -1))
{
  char buf[MAX_PATH_SIZE];
  get_input_file_path(buf, MAX_PATH_SIZE);
  patch_ctx = init_ida_patcher(buf, MAX_PATH_SIZE, ftype);
}

bool idaapi plugin_ctx_t::run(size_t arg)
{
  return true;
}

bool plugin_ctx_t::register_main_action()
{
  return register_action(inline_hook_act);
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  filetype_t filetype = inf_get_filetype();
  Filetype ftype;
  switch (filetype) {
    case f_PE:
      ftype = Filetype::Coff;
      break;
    case f_ELF:
      ftype = Filetype::Elf;
      break;
    default:
      return nullptr;
  }
  plugin_ctx_t *ctx = new plugin_ctx_t(ftype);
  if ( !ctx->register_main_action() )
  {
    msg("Failed to register menu item for <" ACTION_LABEL "> plugin!\n");
    delete ctx;
    return nullptr;
  }
  return ctx;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MOD | PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Patch Binary files with ease",              // long comment about the plugin
  "Binary file patcher\n"
  "Insert inline hooks\n"
  "Create code caves\n",
  "Binmodify",       // the preferred short name of the plugin
  "",              // the preferred hotkey to run the plugin
};
