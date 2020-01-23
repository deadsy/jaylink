//-----------------------------------------------------------------------------
/*

C-Code to support the libjaylink wrapper.

*/
//-----------------------------------------------------------------------------

package libjaylink

/*
#include <libjaylink/libjaylink.h>
#include <stdio.h>

// Go won't allow the "type" field, so this is a C-wrapper.
uint32_t get_hw_type(struct jaylink_hardware_version *h) {
  return (uint32_t)h->type;
}

void goLogCallback(struct jaylink_context *ctx, char *msg);

int LogCallback(const struct jaylink_context *ctx, enum jaylink_log_level level, const char *format, va_list args, void *user_data) {
  // check the log level
  enum jaylink_log_level log_level;
  jaylink_log_get_level(ctx, &log_level);
  if (level > log_level) {
    return 0;
  }
  char msg[128];
  vsnprintf(msg, sizeof(msg), format, args);
  goLogCallback((struct jaylink_context *)ctx, msg);
  return 0;
}

*/
import "C"

//-----------------------------------------------------------------------------
