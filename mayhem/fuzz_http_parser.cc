// libFuzzer harness for gRPC's HTTP/1 request/response parser (src/core/util/http_client/parser.cc), mirroring
// test/core/util/http_client/fuzzer.cc. First byte picks request vs response; the rest is the wire text, fed in
// two pieces to exercise the incremental state machine.
#include <grpc/grpc.h>
#include <grpc/slice.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "src/core/util/http_client/parser.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  grpc_init();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return -1;
  bool response = data[0] & 1;
  size_t cut = (size - 1) ? (data[0] >> 1) % (size) : 0;
  const char* p = reinterpret_cast<const char*>(data + 1);
  size_t n = size - 1;
  if (cut > n) cut = n;

  grpc_http_parser parser;
  grpc_http_request request;
  grpc_http_response resp;
  memset(&request, 0, sizeof(request));
  resp = {};
  if (response) {
    grpc_http_parser_init(&parser, GRPC_HTTP_RESPONSE, &resp);
  } else {
    grpc_http_parser_init(&parser, GRPC_HTTP_REQUEST, &request);
  }
  bool ok = true;
  grpc_slice a = grpc_slice_from_copied_buffer(p, cut);
  grpc_slice b = grpc_slice_from_copied_buffer(p + cut, n - cut);
  ok = ok && (grpc_http_parser_parse(&parser, a, nullptr)).ok();
  ok = ok && (grpc_http_parser_parse(&parser, b, nullptr)).ok();
  if (ok) ok = (grpc_http_parser_eof(&parser)).ok();
  grpc_slice_unref(a);
  grpc_slice_unref(b);
  grpc_http_parser_destroy(&parser);
  if (response) {
    grpc_http_response_destroy(&resp);
  } else {
    grpc_http_request_destroy(&request);
  }
  return ok ? 0 : -1;
}
