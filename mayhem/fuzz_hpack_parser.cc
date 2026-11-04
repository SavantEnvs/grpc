// libFuzzer harness for the HTTP/2 HPACK parser (src/core/ext/transport/chttp2/transport/hpack_parser.cc), mirroring
// test/core/transport/chttp2/hpack_parser_fuzzer.cc (which is protobuf/FuzzTest-driven): a header block is fed to
// HPackParser in two segments, over up to two frames, with metadata limits chosen from the input.
// Layout: [flags][limit][split] then the header block bytes.
#include <grpc/grpc.h>
#include <grpc/slice.h>
#include <stddef.h>
#include <stdint.h>

#include <algorithm>
#include <memory>

#include "absl/random/random.h"
#include "src/core/call/metadata_batch.h"
#include "src/core/ext/transport/chttp2/transport/hpack_parser.h"
#include "src/core/lib/iomgr/error.h"
#include "src/core/lib/iomgr/exec_ctx.h"
#include "src/core/lib/resource_quota/arena.h"
#include "src/core/lib/resource_quota/memory_quota.h"
#include "src/core/lib/resource_quota/resource_quota.h"
#include "src/core/util/grpc_check.h"
#include "src/core/util/status_helper.h"

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  grpc_init();
  return 0;
}

namespace grpc_core {
namespace {

bool ParseSegment(HPackParser* parser, const uint8_t* p, size_t n, bool last,
                  absl::BitGen& bitgen, int absolute_max_length) {
  grpc_slice buffer =
      grpc_slice_from_copied_buffer(reinterpret_cast<const char*>(p), n);
  auto err = parser->Parse(buffer, last, absl::BitGenRef(bitgen),
                           /*call_tracer=*/nullptr);
  grpc_slice_unref(buffer);
  GRPC_CHECK(static_cast<int>(parser->buffered_bytes() / 4) <
             std::max(1024, absolute_max_length));
  if (!err.ok()) {
    intptr_t unused;
    // A stream error is recoverable; a connection error ends the connection.
    if (!grpc_error_get_int(err, StatusIntProperty::kStreamId, &unused)) {
      return false;
    }
  }
  return true;
}

}  // namespace
}  // namespace grpc_core

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  using namespace grpc_core;
  if (size < 4) return -1;
  uint8_t flags = data[0], limit = data[1], split = data[2];
  data += 3;
  size -= 3;
  int max_length = 64 + 16 * (limit & 0x0f);
  int absolute_max_length = max_length + 64 * (limit >> 4);
  size_t cut = size == 0 ? 0 : split % (size + 1);

  auto memory_allocator =
      ResourceQuota::Default()->memory_quota()->CreateMemoryAllocator(
          "fuzz-allocator");
  absl::BitGen bitgen;
  bool alive = true;
  {
    std::unique_ptr<HPackParser> parser(new HPackParser);
    for (int frame = 0; frame < 2 && alive; frame++) {
      auto arena = SimpleArenaAllocator()->MakeArena();
      ExecCtx exec_ctx;
      grpc_metadata_batch b;
      HPackParser::Boundary boundary = HPackParser::Boundary::None;
      if (frame == 1 || (flags & 1)) {
        boundary = (flags & 2) ? HPackParser::Boundary::EndOfStream
                               : HPackParser::Boundary::EndOfHeaders;
      }
      HPackParser::Priority priority = (flags & 4) && frame == 0
                                           ? HPackParser::Priority::Included
                                           : HPackParser::Priority::None;
      parser->BeginFrame(
          &b, max_length, absolute_max_length, boundary, priority,
          HPackParser::LogInfo{1, HPackParser::LogInfo::kHeaders, false},
          nullptr);
      // Frame 0 gets the whole block in two pieces; frame 1 replays it whole.
      if (frame == 0) {
        alive = ParseSegment(parser.get(), data, cut, false, bitgen,
                             absolute_max_length) &&
                ParseSegment(parser.get(), data + cut, size - cut, true,
                             bitgen, absolute_max_length);
      } else {
        alive = ParseSegment(parser.get(), data, size, true, bitgen,
                             absolute_max_length);
      }
      if (alive && (flags & 8) == 0) parser->StopBufferingFrame();
      parser->FinishFrame();
    }
  }
  return alive ? 0 : -1;
}
