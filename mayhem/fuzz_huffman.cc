// libFuzzer harness for the HPACK Huffman coder (src/core/ext/transport/chttp2/transport/{bin_encoder,decode_huff}),
// mirroring test/core/transport/chttp2/huff_fuzzer.cc: encode/decode must round-trip, and the table-driven
// decoder must agree with a bit-by-bit reference decoder over grpc_chttp2_huffsyms.
#include <grpc/slice.h>
#include <stddef.h>
#include <stdint.h>

#include <optional>
#include <vector>

#include "src/core/ext/transport/chttp2/transport/bin_encoder.h"
#include "src/core/ext/transport/chttp2/transport/decode_huff.h"
#include "src/core/ext/transport/chttp2/transport/huffsyms.h"
#include "src/core/util/grpc_check.h"

namespace {

std::optional<std::vector<uint8_t>> DecodeHuffSlow(const uint8_t* begin,
                                                   const uint8_t* end) {
  uint64_t bits = 0;
  size_t bits_left = 0u;
  std::vector<uint8_t> out;
  while (true) {
    while (begin != end && bits_left < 30) {
      bits <<= 8;
      bits |= begin[0];
      ++begin;
      bits_left += 8;
    }
    if (bits_left < 5) break;
    bool found = false;
    for (int i = 0; i < GRPC_CHTTP2_NUM_HUFFSYMS; i++) {
      const auto& sym = grpc_chttp2_huffsyms[i];
      if (sym.length > bits_left) continue;
      if (((bits >> (bits_left - sym.length)) & ((1 << sym.length) - 1)) ==
          sym.bits) {
        found = true;
        bits_left -= sym.length;
        if (i == 256) {
          return out;
        }
        out.push_back(i);
        break;
      }
    }
    if (!found) {
      break;
    }
  }
  while (bits_left > 0) {
    if ((bits & 1) == 0) {
      return std::nullopt;
    }
    bits >>= 1;
    bits_left--;
  }
  return out;
}

std::optional<std::vector<uint8_t>> DecodeHuffFast(const uint8_t* begin,
                                                   const uint8_t* end) {
  std::vector<uint8_t> v;
  auto f = [&](uint8_t x) { v.push_back(x); };
  if (!grpc_core::HuffDecoder<decltype(f)>(f, begin, end).Run()) {
    return std::nullopt;
  }
  return v;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::vector<uint8_t> buffer(data, data + size);

  {
    grpc_slice uncompressed = grpc_slice_from_copied_buffer(
        reinterpret_cast<const char*>(buffer.data()), buffer.size());
    grpc_slice compressed = grpc_chttp2_huffman_compress(uncompressed);
    std::vector<uint8_t> again;
    auto add = [&again](uint8_t c) { again.push_back(c); };
    GRPC_CHECK((grpc_core::HuffDecoder<decltype(add)>(
                    add, GRPC_SLICE_START_PTR(compressed),
                    GRPC_SLICE_END_PTR(compressed))
                    .Run()));
    GRPC_CHECK(again == buffer);
    grpc_slice_unref(uncompressed);
    grpc_slice_unref(compressed);
  }

  auto slow = DecodeHuffSlow(buffer.data(), buffer.data() + buffer.size());
  auto fast = DecodeHuffFast(buffer.data(), buffer.data() + buffer.size());
  GRPC_CHECK(fast == slow);
  return fast.has_value() ? 0 : -1;
}
