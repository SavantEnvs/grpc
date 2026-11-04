// libFuzzer harness for service-config JSON parsing (src/core/service_config/service_config_impl.cc), which pulls in
// the registered parsers for retry, method config, LB policies and health checking. A config that parses must
// keep its JSON string.
#include <grpc/grpc.h>
#include <stddef.h>
#include <stdint.h>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/service_config/service_config.h"
#include "src/core/service_config/service_config_impl.h"
#include "src/core/util/grpc_check.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  grpc_init();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  absl::string_view text(reinterpret_cast<const char*>(data), size);
  auto config = grpc_core::ServiceConfigImpl::Create(grpc_core::ChannelArgs(), text);
  if (!config.ok()) return -1;
  GRPC_CHECK((*config)->json_string() == text);
  return 0;
}
