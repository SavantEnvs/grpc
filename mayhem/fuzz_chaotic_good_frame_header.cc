// libFuzzer harness for the chaotic-good transport framing (src/core/ext/transport/chaotic_good/): the two TCP frame
// headers (tcp_frame_header.cc), mirroring test/core/transport/chaotic_good/tcp_frame_header_fuzzer.cc, and the frame
// codec that decodes what follows a header (frame.cc: ParseFrame, the protobuf payloads, the metadata conversion).
// Byte 0 % 3 picks the mode: 0 control-channel header, 1 data-channel header, 2 frame body. A header that parses must
// serialize back to the exact same bytes; a frame that parses must re-serialize to a frame that parses to the same
// value.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <utility>
#include <variant>

#include "absl/status/statusor.h"
#include "absl/types/variant.h"
#include "src/core/ext/transport/chaotic_good/frame.h"
#include "src/core/ext/transport/chaotic_good/frame_header.h"
#include "src/core/ext/transport/chaotic_good/tcp_frame_header.h"
#include "src/core/lib/slice/slice.h"
#include "src/core/lib/slice/slice_buffer.h"
#include "src/core/util/grpc_check.h"

using grpc_core::SliceBuffer;
using grpc_core::chaotic_good::ClientInitialMetadataFrame;
using grpc_core::chaotic_good::Frame;
using grpc_core::chaotic_good::FrameHeader;
using grpc_core::chaotic_good::FrameInterface;
using grpc_core::chaotic_good::FrameType;
using grpc_core::chaotic_good::ServerInitialMetadataFrame;
using grpc_core::chaotic_good::ServerTrailingMetadataFrame;
using grpc_core::chaotic_good::TcpDataFrameHeader;
using grpc_core::chaotic_good::TcpFrameHeader;

namespace {

uint32_t ReadU32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 | static_cast<uint32_t>(p[2]) << 16 |
         static_cast<uint32_t>(p[3]) << 24;
}

// Bytes 1.. are: frame type (1), stream id (4, little endian), payload. The transport reads exactly
// header.payload_length payload bytes before calling ParseFrame, so the length handed to ParseFrame is the length of
// the payload it gets (a mismatch is rejected by ParseFrame and unreachable from a real connection).
int FuzzFrame(const uint8_t* data, size_t size) {
  if (size < 5) return -1;
  FrameHeader header;
  header.type = static_cast<FrameType>(data[0]);
  header.stream_id = ReadU32(data + 1);
  data += 5;
  size -= 5;
  header.payload_length = static_cast<uint32_t>(size);
  SliceBuffer payload;
  payload.Append(grpc_core::Slice::FromCopiedBuffer(reinterpret_cast<const char*>(data), size));
  auto frame = grpc_core::chaotic_good::ParseFrame(header, std::move(payload));
  if (!frame.ok()) return -1;

  // The receive path turns a metadata frame's protobuf into a metadata batch.
  if (auto* f = std::get_if<ClientInitialMetadataFrame>(&*frame)) {
    (void)grpc_core::chaotic_good::ClientMetadataGrpcFromProto(f->body);
  } else if (auto* f = std::get_if<ServerInitialMetadataFrame>(&*frame)) {
    (void)grpc_core::chaotic_good::ServerMetadataGrpcFromProto(f->body);
  } else if (auto* f = std::get_if<ServerTrailingMetadataFrame>(&*frame)) {
    (void)grpc_core::chaotic_good::ServerMetadataGrpcFromProto(f->body);
  }

  const FrameInterface& fi = absl::ConvertVariantTo<const FrameInterface&>(*frame);
  FrameHeader out_header = fi.MakeHeader();
  SliceBuffer out_payload;
  fi.SerializePayload(out_payload);
  GRPC_CHECK_EQ(out_header.payload_length, out_payload.Length());
  GRPC_CHECK(out_header.type == header.type);
  auto again = grpc_core::chaotic_good::ParseFrame(out_header, std::move(out_payload));
  GRPC_CHECK(again.ok());
  GRPC_CHECK(absl::ConvertVariantTo<const FrameInterface&>(*frame).ToString() ==
             absl::ConvertVariantTo<const FrameInterface&>(*again).ToString());
  return 0;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) return -1;
  const uint8_t mode = data[0] % 3;
  data++;
  size--;
  if (mode == 2) return FuzzFrame(data, size);
  if (mode == 1) {
    uint8_t buf[TcpDataFrameHeader::kFrameHeaderSize] = {};
    memcpy(buf, data, size < sizeof(buf) ? size : sizeof(buf));
    auto h = TcpDataFrameHeader::Parse(buf);
    if (!h.ok()) return -1;
    uint8_t out[TcpDataFrameHeader::kFrameHeaderSize];
    h->Serialize(out);
    GRPC_CHECK(memcmp(buf, out, sizeof(buf)) == 0);
  } else {
    uint8_t buf[TcpFrameHeader::kFrameHeaderSize] = {};
    memcpy(buf, data, size < sizeof(buf) ? size : sizeof(buf));
    auto h = TcpFrameHeader::Parse(buf);
    if (!h.ok()) return -1;
    uint8_t out[TcpFrameHeader::kFrameHeaderSize];
    h->Serialize(out);
    GRPC_CHECK(memcmp(buf, out, sizeof(buf)) == 0);
  }
  return 0;
}
