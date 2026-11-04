// libFuzzer harness for gRPC's address parsing (src/core/lib/address_utils/parse_address.cc, sockaddr_utils.cc).
// Mode 0: URI string -> grpc_parse_uri -> grpc_sockaddr_to_uri must itself parse (mirrors
// test/core/address_utils/sockaddr_utils_fuzzer_test.cc). Mode 1: host:port text -> StringToSockaddr, and the
// resolved address must re-serialize. Mode 2: raw sockaddr bytes -> grpc_sockaddr_to_uri (upstream's exact case).
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "absl/status/statusor.h"
#include "src/core/lib/address_utils/parse_address.h"
#include "src/core/lib/address_utils/sockaddr_utils.h"
#include "src/core/lib/iomgr/resolved_address.h"
#include "src/core/util/grpc_check.h"
#include "src/core/util/uri.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  uint8_t mode = data[0] % 3;
  const char* p = reinterpret_cast<const char*>(data + 1);
  size_t n = size - 1;
  if (mode == 0) {
    auto uri = grpc_core::URI::Parse(std::string(p, n));
    if (!uri.ok()) return -1;
    grpc_resolved_address addr;
    memset(&addr, 0, sizeof(addr));
    if (!grpc_parse_uri(*uri, &addr)) return -1;
    auto out = grpc_sockaddr_to_uri(&addr);
    if (out.ok()) GRPC_CHECK_OK(grpc_core::URI::Parse(*out));
    return 0;
  }
  if (mode == 1) {
    auto addr = grpc_core::StringToSockaddr(std::string(p, n));
    if (!addr.ok()) return -1;
    auto str = grpc_sockaddr_to_string(&*addr, false);
    GRPC_CHECK_OK(str);
    auto uri = grpc_sockaddr_to_uri(&*addr);
    GRPC_CHECK_OK(uri);
    GRPC_CHECK_OK(grpc_core::URI::Parse(*uri));
    return 0;
  }
  if (n < 1 || n > GRPC_MAX_SOCKADDR_SIZE) return -1;
  grpc_resolved_address address;
  memset(&address, 0, sizeof(address));
  memcpy(address.addr, p, n);
  address.len = n;
  auto uri = grpc_sockaddr_to_uri(&address);
  if (!uri.ok()) return -1;
  GRPC_CHECK_OK(grpc_core::URI::Parse(*uri));
  return 0;
}
