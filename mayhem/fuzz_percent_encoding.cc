// libFuzzer harness for gRPC's percent encoding (src/core/lib/slice/percent_encoding.cc), mirroring
// test/core/slice/percent_encode_fuzzer.cc. First byte selects the mode; the rest is the payload.
#include <grpc/grpc.h>
#include <stddef.h>
#include <stdint.h>

#include <utility>

#include "src/core/lib/slice/percent_encoding.h"
#include "src/core/lib/slice/slice.h"
#include "src/core/util/grpc_check.h"

using grpc_core::PercentEncodingType;
using grpc_core::Slice;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  uint8_t mode = data[0];
  const char* payload = reinterpret_cast<const char*>(data + 1);
  size_t payload_size = size - 1;
  if (mode & 1) {
    PercentEncodingType type =
        (mode & 2) ? PercentEncodingType::URL : PercentEncodingType::Compatible;
    Slice input = Slice::FromCopiedBuffer(payload, payload_size);
    Slice encoded = grpc_core::PercentEncodeSlice(input.Ref(), type);
    Slice decoded = grpc_core::PermissivePercentDecodeSlice(std::move(encoded));
    GRPC_CHECK(input == decoded);
  } else {
    (void)grpc_core::PermissivePercentDecodeSlice(
        Slice::FromCopiedBuffer(payload, payload_size));
  }
  return 0;
}
