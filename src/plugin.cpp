#include "plugin.h"
#include <cstddef>

#define ACTION_NAME "binmodify:InlineHook"
#define ACTION_LABEL "Add inline hook"

int idaapi inline_hook_ah_t::activate(action_activation_ctx_t *) {
  qstring patch;
  if (!ask_str(&patch, 0, "Bytes to insert")) {
    return false;
  }
  if ((patch.size() % 2) != 1) {
    warning("Patch must be formatted as lowercase hex string (must have even number of characters)");
    return false;
  }
  std::vector<uint8_t> patch_bytes((patch.size() - 1)/2);
  for (uint16_t i = 0; i < patch.size() - 1; i += 2) {
      char c0 = patch[i];
      char c1 = patch[i+1];
      uint8_t b = 0;
      if (('0' <= c0) && ('9' >= c0))
        b |= (c0 - '0') << 4;
      else if (('a' <= c0) && ('f' >= c0))
        b |= (c0 - 'a') << 4;
      else {
        warning("Patch must be formatted as lowercase hex string (character %c (%d) is not hex)", c0, i);
        return false;
    }
      if (('0' <= c1) && ('9' >= c1))
        b |= c1 - '0';
      else if (('a' <= c1) && ('f' >= c1))
        b |= c1 - 'a';
      else {
        warning("Patch must be formatted as lowercase hex string (character %c (%d) is not hex)", c1, i+1);
        return false;
      }
      patch_bytes[i/2] = b;
  }
  pure_patch(ctx.patch_ctx, get_screen_ea(), patch_bytes.data(), patch_bytes.size());
  return true;
}

action_state_t idaapi inline_hook_ah_t::update(action_update_ctx_t * update_ctx) {
    if ((update_ctx) && (update_ctx->widget_type == BWN_DISASM))
      return AST_ENABLE_ALWAYS;
    return AST_DISABLE;
  }

#define MAX_PATH_SIZE 100

plugin_ctx_t::plugin_ctx_t(Filetype ftype, void*_patch_ctx)
  : inline_hook_act(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        ACTION_LABEL,
        &inline_hook_ah,
        this,
        "Shift+I",
        "Insert an inline hook which jumps to provided code and then returns", -1)), patch_ctx(_patch_ctx)
{
}

//---------------------------------------------------------------------------
// Callback for ui notifications
static ssize_t idaapi ui_callback(void *ud, int notification_code, va_list va)
{
  switch ( notification_code )
  {
    // called when IDA is preparing a context menu for a view
    // Here dynamic context-depending user menu items can be added.
    case ui_populating_widget_popup:
      {
        TWidget *view = va_arg(va, TWidget *);
        if ( get_widget_type(view) == BWN_DISASM )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          attach_action_to_popup(view, p, ACTION_NAME);
        }
      }
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
plugin_ctx_t::~plugin_ctx_t()
{
  deinit_ida_patcher(patch_ctx);
  unhook_from_notification_point(HT_UI, ui_callback, this);
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
  char buf[MAX_PATH_SIZE];
  void* patch_ctx = init_ida_patcher(buf, get_input_file_path(buf, MAX_PATH_SIZE) - 1, ftype);
  if (patch_ctx == NULL) 
  {
    msg("Failed to init ida_patcher\n");
    return nullptr;
  }
  plugin_ctx_t *ctx = new plugin_ctx_t(ftype, patch_ctx);
  if ( !ctx->register_main_action() )
  {
    msg("Failed to register menu item for <" ACTION_LABEL "> plugin!\n");
    delete ctx;
    return nullptr;
  }
  hook_to_notification_point(HT_UI, ui_callback, ctx);
  #ifdef __EA64__
  msg("Binmodify 64bit loaded.\n");
  #else
  msg("Binmodify 32bit loaded.\n");
  #endif
  return ctx;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
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
