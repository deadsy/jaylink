//-----------------------------------------------------------------------------
/*

C-Code to support the libjaylink wrapper.

Note: https://golang.org/cmd/cgo/#hdr-C_references_to_Go

Using //export in a file places a restriction on the preamble:
since it is copied into two different C output files, it must not contain
any definitions, only declarations. If a file contains both definitions and
declarations, then the two output files will produce duplicate symbols and
the linker will fail. To avoid this, definitions must be placed in preambles
in other files, or in C source files.

*/
//-----------------------------------------------------------------------------

package jaylink

/*
#include <libjaylink/libjaylink.h>
#include <stdio.h>

// Go won't allow the "type" field, so this is a C-wrapper.
uint32_t get_hw_type(struct jaylink_hardware_version *h) {
  return (uint32_t)h->type;
}

void goLogCallback(struct jaylink_context *ctx, char *msg);

int LogCallback(const struct jaylink_context *ctx, enum jaylink_log_level level,
  const char *format, va_list args, void *user_data) {
  // check the log level
  enum jaylink_log_level log_level;
  jaylink_log_get_level(ctx, &log_level);
  if (level > log_level) {
    return 0;
  }
  // create the message string
  char msg[128];
  vsnprintf(msg, sizeof(msg), format, args);
  // callback to go
  goLogCallback((struct jaylink_context *)ctx, msg);
  return 0;
}

*/
import "C"

//-----------------------------------------------------------------------------
