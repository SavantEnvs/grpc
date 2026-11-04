// libFuzzer harness for gRPC's JSON reader/writer (src/core/util/json/json_reader.cc, json_writer.cc): a document
// that parses must dump to text that parses back to an equal document.
#include <stddef.h>
#include <stdint.h>

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "src/core/util/grpc_check.h"
#include "src/core/util/json/json.h"
#include "src/core/util/json/json_reader.h"
#include "src/core/util/json/json_writer.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  absl::string_view text(reinterpret_cast<const char*>(data), size);
  auto json = grpc_core::JsonParse(text);
  if (!json.ok()) return -1;
  std::string dumped = grpc_core::JsonDump(*json);
  auto again = grpc_core::JsonParse(dumped);
  GRPC_CHECK_OK(again);
  GRPC_CHECK(*json == *again);
  GRPC_CHECK(grpc_core::JsonDump(*again) == dumped);
  return 0;
}
