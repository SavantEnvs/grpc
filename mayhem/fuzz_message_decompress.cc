// libFuzzer harness for grpc_msg_decompress (src/core/lib/compression/message_compress.cc), mirroring
// test/core/compression/message_decompress_fuzzer.cc. First byte selects the algorithm (identity, deflate, gzip).
#include <grpc/compression.h>
#include <grpc/grpc.h>
#include <grpc/slice.h>
#include <grpc/slice_buffer.h>
#include <stddef.h>
#include <stdint.h>

#include "src/core/lib/compression/message_compress.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  grpc_init();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 2) return -1;
  static const grpc_compression_algorithm kAlgs[] = {
      GRPC_COMPRESS_NONE, GRPC_COMPRESS_DEFLATE, GRPC_COMPRESS_GZIP};
  grpc_compression_algorithm alg = kAlgs[data[0] % 3];
  grpc_slice_buffer input_buffer;
  grpc_slice_buffer_init(&input_buffer);
  grpc_slice_buffer_add(&input_buffer,
                        grpc_slice_from_copied_buffer(
                            reinterpret_cast<const char*>(data + 1), size - 1));
  grpc_slice_buffer output_buffer;
  grpc_slice_buffer_init(&output_buffer);
  int ok = grpc_msg_decompress(alg, &input_buffer, &output_buffer);
  grpc_slice_buffer_destroy(&input_buffer);
  grpc_slice_buffer_destroy(&output_buffer);
  return ok ? 0 : -1;
}
