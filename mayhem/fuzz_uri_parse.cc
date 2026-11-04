// libFuzzer harness for grpc_core::URI::Parse (src/core/util/uri.cc), mirroring
// test/core/util/uri_fuzzer_test.cc: a URI that parses must re-serialize to a URI that parses to the same parts.
#include <stddef.h>
#include <stdint.h>

#include <string>

#include "absl/status/statusor.h"
#include "src/core/util/grpc_check.h"
#include "src/core/util/uri.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string buffer(reinterpret_cast<const char*>(data), size);
  auto uri = grpc_core::URI::Parse(buffer);
  if (!uri.ok()) return -1;
  std::string buffer2 = uri->ToString();
  auto uri2 = grpc_core::URI::Parse(buffer2);
  GRPC_CHECK_OK(uri2);
  GRPC_CHECK(uri->ToString() == uri2->ToString());
  GRPC_CHECK(uri->scheme() == uri2->scheme());
  GRPC_CHECK(uri->authority() == uri2->authority());
  GRPC_CHECK(uri->user_info() == uri2->user_info());
  GRPC_CHECK(uri->host_port() == uri2->host_port());
  GRPC_CHECK(uri->path() == uri2->path());
  GRPC_CHECK(uri->query_parameter_pairs() == uri2->query_parameter_pairs());
  GRPC_CHECK(uri->fragment() == uri2->fragment());
  GRPC_CHECK(*uri == *uri2);
  return 0;
}
