// Known-answer self-test for the gRPC core code paths the fuzz targets exercise. Built by build.sh against a
// NORMAL-flags (unsanitized) libgrpc and run by test.sh, which parses the PASS/FAIL lines. Every expectation is a
// fixed literal (RFC 7541 appendix C vectors, hand-computed encodings), never derived from the code under test.
#include <grpc/compression.h>
#include <grpc/grpc.h>
#include <grpc/slice.h>
#include <grpc/slice_buffer.h>
#include <stdint.h>
#include <string.h>

#include <cstdio>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "src/core/ext/transport/chaotic_good/tcp_frame_header.h"
#include "src/core/ext/transport/chttp2/transport/bin_encoder.h"
#include "src/core/ext/transport/chttp2/transport/decode_huff.h"
#include "src/core/lib/address_utils/parse_address.h"
#include "src/core/lib/address_utils/sockaddr_utils.h"
#include "src/core/lib/channel/channel_args.h"
#include "src/core/lib/compression/message_compress.h"
#include "src/core/lib/iomgr/resolved_address.h"
#include "src/core/lib/slice/percent_encoding.h"
#include "src/core/lib/slice/slice.h"
#include "src/core/service_config/service_config_impl.h"
#include "src/core/util/http_client/parser.h"
#include "src/core/util/json/json_reader.h"
#include "src/core/util/json/json_writer.h"
#include "src/core/util/uri.h"

namespace {

int g_pass = 0, g_fail = 0;

void Report(const char* name, bool ok, const std::string& detail = "") {
  if (ok) {
    g_pass++;
    printf("PASS %s\n", name);
  } else {
    g_fail++;
    printf("FAIL %s %s\n", name, detail.c_str());
  }
}

template <typename T>
void ExpectEq(const char* name, const T& got, const T& want) {
  Report(name, got == want);
}

void ExpectStr(const char* name, const std::string& got, const std::string& want) {
  Report(name, got == want, "got [" + absl::CEscape(got) + "] want [" + absl::CEscape(want) + "]");
}

std::string HuffEncode(const std::string& s) {
  grpc_slice in = grpc_slice_from_copied_buffer(s.data(), s.size());
  grpc_slice out = grpc_chttp2_huffman_compress(in);
  std::string r(reinterpret_cast<const char*>(GRPC_SLICE_START_PTR(out)), GRPC_SLICE_LENGTH(out));
  grpc_slice_unref(in);
  grpc_slice_unref(out);
  return r;
}

std::string HuffDecode(const std::string& s, bool* ok) {
  std::string out;
  auto add = [&out](uint8_t c) { out.push_back(static_cast<char>(c)); };
  const uint8_t* b = reinterpret_cast<const uint8_t*>(s.data());
  *ok = grpc_core::HuffDecoder<decltype(add)>(add, b, b + s.size()).Run();
  return out;
}

std::string Hex(const std::string& s) { return absl::BytesToHexString(s); }

std::string FromHex(const std::string& h) {
  std::string out;
  return absl::HexStringToBytes(h, &out) ? out : std::string();
}

void TestUri() {
  auto u = grpc_core::URI::Parse("https://user@example.com:8080/a%20b/c?x=1&y=2#frag");
  Report("uri.parse_ok", u.ok());
  if (!u.ok()) return;
  ExpectStr("uri.scheme", u->scheme(), "https");
  ExpectStr("uri.authority", u->authority(), "user@example.com:8080");
  ExpectStr("uri.user_info", u->user_info(), "user");
  ExpectStr("uri.host_port", u->host_port(), "example.com:8080");
  ExpectStr("uri.path_decoded", u->path(), "/a b/c");
  ExpectStr("uri.fragment", u->fragment(), "frag");
  Report("uri.query_pairs", u->query_parameter_pairs().size() == 2 &&
                                u->query_parameter_pairs()[0].key == "x" &&
                                u->query_parameter_pairs()[0].value == "1" &&
                                u->query_parameter_pairs()[1].key == "y" &&
                                u->query_parameter_pairs()[1].value == "2");
  ExpectStr("uri.to_string", u->ToString(), "https://user@example.com:8080/a%20b/c?x=1&y=2#frag");
  Report("uri.reject_no_scheme", !grpc_core::URI::Parse("no-scheme-here").ok());
  Report("uri.reject_empty_scheme", !grpc_core::URI::Parse("://host/path").ok());
  ExpectStr("uri.percent_decode", grpc_core::URI::PercentDecode("a%2Fb%41"), "a/bA");
}

void TestPercentEncoding() {
  using grpc_core::PercentEncodingType;
  using grpc_core::Slice;
  std::string in("a b/\xc3\xa9~%\n", 9);
  auto enc = [&](PercentEncodingType t) {
    Slice o = grpc_core::PercentEncodeSlice(Slice::FromCopiedBuffer(in.data(), in.size()), t);
    return std::string(o.as_string_view());
  };
  ExpectStr("percent.url", enc(PercentEncodingType::URL), "a%20b%2F%C3%A9~%25%0A");
  ExpectStr("percent.compatible", enc(PercentEncodingType::Compatible), "a b/%C3%A9~%25%0A");
  Slice d = grpc_core::PermissivePercentDecodeSlice(Slice::FromCopiedBuffer("x%20y%zz%4", 10));
  ExpectStr("percent.permissive_decode", std::string(d.as_string_view()), "x y%zz%4");
}

void TestHuffman() {
  ExpectStr("huff.rfc7541_c41", Hex(HuffEncode("www.example.com")), "f1e3c2e5f23a6ba0ab90f4ff");
  ExpectStr("huff.rfc7541_c42", Hex(HuffEncode("no-cache")), "a8eb10649cbf");
  ExpectStr("huff.rfc7541_c61", Hex(HuffEncode("custom-key")), "25a849e95ba97d7f");
  bool ok = false;
  std::string d = HuffDecode(FromHex("f1e3c2e5f23a6ba0ab90f4ff"), &ok);
  Report("huff.decode_ok", ok);
  ExpectStr("huff.decode", d, "www.example.com");
  HuffDecode(FromHex("00"), &ok);
  Report("huff.reject_bad_padding", !ok);
  ExpectStr("base64.encode", [] {
    grpc_slice in = grpc_slice_from_static_string("Many hands make light work.");
    grpc_slice out = grpc_chttp2_base64_encode(in);
    std::string r(reinterpret_cast<const char*>(GRPC_SLICE_START_PTR(out)), GRPC_SLICE_LENGTH(out));
    grpc_slice_unref(out);
    return r;
  }(), "TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu");
}

std::string Decompress(grpc_compression_algorithm alg, const std::string& in, bool* ok) {
  grpc_slice_buffer src, dst;
  grpc_slice_buffer_init(&src);
  grpc_slice_buffer_init(&dst);
  grpc_slice_buffer_add(&src, grpc_slice_from_copied_buffer(in.data(), in.size()));
  *ok = grpc_msg_decompress(alg, &src, &dst) != 0;
  std::string out;
  for (size_t i = 0; i < dst.count; i++) {
    out.append(reinterpret_cast<const char*>(GRPC_SLICE_START_PTR(dst.slices[i])),
               GRPC_SLICE_LENGTH(dst.slices[i]));
  }
  grpc_slice_buffer_destroy(&src);
  grpc_slice_buffer_destroy(&dst);
  return out;
}

void TestCompression() {
  static const uint8_t kGzip[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x48, 0x2f, 0x2a, 0x48, 0x56, 0xc8, 0x80, 0x33, 0xb9, 0x00, 0x32, 0x2c, 0x9c, 0x54, 0x16, 0x00, 0x00, 0x00};
  bool ok = false;
  std::string d = Decompress(GRPC_COMPRESS_GZIP, std::string(reinterpret_cast<const char*>(kGzip), sizeof(kGzip)), &ok);
  Report("gzip.decompress_ok", ok);
  ExpectStr("gzip.decompress", d, "hello grpc hello grpc\n");
  Decompress(GRPC_COMPRESS_GZIP, "this is not gzip data", &ok);
  Report("gzip.reject_garbage", !ok);
  std::string big(1000, 'a');
  grpc_slice_buffer src, dst;
  grpc_slice_buffer_init(&src);
  grpc_slice_buffer_init(&dst);
  grpc_slice_buffer_add(&src, grpc_slice_from_copied_buffer(big.data(), big.size()));
  int rc = grpc_msg_compress(GRPC_COMPRESS_DEFLATE, &src, &dst);
  Report("deflate.compress_shrinks", rc != 0 && dst.length > 0 && dst.length < 50);
  grpc_slice_buffer back;
  grpc_slice_buffer_init(&back);
  Report("deflate.roundtrip_ok", grpc_msg_decompress(GRPC_COMPRESS_DEFLATE, &dst, &back) != 0);
  Report("deflate.roundtrip_len", back.length == 1000);
  grpc_slice_buffer_destroy(&src);
  grpc_slice_buffer_destroy(&dst);
  grpc_slice_buffer_destroy(&back);
}

void TestJson() {
  auto j = grpc_core::JsonParse(R"({ "a" : [1, 2, {"b": null}], "c": "dé", "e": true })");
  Report("json.parse_ok", j.ok());
  if (j.ok()) {
    ExpectStr("json.dump", grpc_core::JsonDump(*j), "{\"a\":[1,2,{\"b\":null}],\"c\":\"d\\u00e9\",\"e\":true}");
    Report("json.object_member", j->object().at("c").string() == "d\xc3\xa9");
  }
  Report("json.reject_trailing_comma", !grpc_core::JsonParse("[1,2,]").ok());
  Report("json.reject_unterminated", !grpc_core::JsonParse("{\"a\":").ok());
}

void TestSockaddr() {
  auto a = grpc_core::StringToSockaddr("1.2.3.4:80");
  Report("sockaddr.ipv4_parse", a.ok());
  if (a.ok()) {
    auto s = grpc_sockaddr_to_string(&*a, false);
    ExpectStr("sockaddr.ipv4_string", s.ok() ? *s : "", "1.2.3.4:80");
    auto u = grpc_sockaddr_to_uri(&*a);
    ExpectStr("sockaddr.ipv4_uri", u.ok() ? *u : "", "ipv4:1.2.3.4:80");
  }
  auto b = grpc_core::StringToSockaddr("[::1]:443");
  Report("sockaddr.ipv6_parse", b.ok());
  if (b.ok()) {
    auto s = grpc_sockaddr_to_string(&*b, false);
    ExpectStr("sockaddr.ipv6_string", s.ok() ? *s : "", "[::1]:443");
    auto u = grpc_sockaddr_to_uri(&*b);
    ExpectStr("sockaddr.ipv6_uri", u.ok() ? *u : "", "ipv6:%5B::1%5D:443");
  }
  Report("sockaddr.reject_bad_ip", !grpc_core::StringToSockaddr("999.1.1.1:80").ok());
  auto uri = grpc_core::URI::Parse("unix:/tmp/grpc.sock");
  grpc_resolved_address r;
  memset(&r, 0, sizeof(r));
  Report("sockaddr.unix_parse", uri.ok() && grpc_parse_uri(*uri, &r));
  auto us = grpc_sockaddr_to_uri(&r);
  ExpectStr("sockaddr.unix_uri", us.ok() ? *us : "", "unix:/tmp/grpc.sock");
}

void TestHttp() {
  grpc_http_parser parser;
  grpc_http_response resp;
  grpc_http_parser_init(&parser, GRPC_HTTP_RESPONSE, &resp);
  const char* text = "HTTP/1.1 404 Not Found\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello";
  grpc_slice s = grpc_slice_from_static_string(text);
  Report("http.parse_ok", grpc_http_parser_parse(&parser, s, nullptr).ok());
  Report("http.eof_ok", grpc_http_parser_eof(&parser).ok());
  Report("http.status", resp.status == 404);
  Report("http.body", resp.body_length == 5 && memcmp(resp.body, "hello", 5) == 0);
  Report("http.headers", resp.hdr_count == 2 && std::string(resp.hdrs[0].key) == "Content-Length" &&
                             std::string(resp.hdrs[0].value) == "5" && std::string(resp.hdrs[1].key) == "X-Test" &&
                             std::string(resp.hdrs[1].value) == "yes");
  grpc_slice_unref(s);
  grpc_http_parser_destroy(&parser);
  grpc_http_response_destroy(&resp);

  grpc_http_parser rp;
  grpc_http_request req;
  memset(&req, 0, sizeof(req));
  grpc_http_parser_init(&rp, GRPC_HTTP_REQUEST, &req);
  grpc_slice s2 = grpc_slice_from_static_string("POST /upload HTTP/1.0\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc");
  Report("http.request_parse_ok", grpc_http_parser_parse(&rp, s2, nullptr).ok());
  Report("http.request_method_path", req.method != nullptr && std::string(req.method) == "POST" &&
                                         req.path != nullptr && std::string(req.path) == "/upload");
  Report("http.request_body", req.body_length == 3 && memcmp(req.body, "abc", 3) == 0);
  grpc_slice_unref(s2);
  grpc_http_parser_destroy(&rp);
  grpc_http_request_destroy(&req);

  grpc_http_parser bp;
  grpc_http_response bad;
  grpc_http_parser_init(&bp, GRPC_HTTP_RESPONSE, &bad);
  grpc_slice s3 = grpc_slice_from_static_string("garbage that is not http\r\n\r\n");
  Report("http.reject_garbage", !grpc_http_parser_parse(&bp, s3, nullptr).ok());
  grpc_slice_unref(s3);
  grpc_http_parser_destroy(&bp);
  grpc_http_response_destroy(&bad);
}

void TestServiceConfig() {
  const char* good =
      R"({"methodConfig":[{"name":[{"service":"foo","method":"bar"}],"timeout":"1.5s","waitForReady":true}],)"
      R"("loadBalancingConfig":[{"round_robin":{}}]})";
  auto c = grpc_core::ServiceConfigImpl::Create(grpc_core::ChannelArgs(), good);
  Report("service_config.valid", c.ok());
  if (c.ok()) ExpectStr("service_config.json_string", std::string((*c)->json_string()), good);
  Report("service_config.reject_bad_timeout",
         !grpc_core::ServiceConfigImpl::Create(grpc_core::ChannelArgs(),
                                               R"({"methodConfig":[{"name":[{"service":"foo"}],"timeout":"abc"}]})")
              .ok());
  Report("service_config.reject_not_object",
         !grpc_core::ServiceConfigImpl::Create(grpc_core::ChannelArgs(), "[1,2,3]").ok());
}

void TestChaoticGood() {
  using grpc_core::chaotic_good::FrameType;
  using grpc_core::chaotic_good::TcpDataFrameHeader;
  using grpc_core::chaotic_good::TcpFrameHeader;
  TcpFrameHeader h;
  h.header.type = FrameType::kMessage;
  h.header.stream_id = 5;
  h.header.payload_length = 100;
  h.payload_tag = 7;
  uint8_t buf[TcpFrameHeader::kFrameHeaderSize];
  h.Serialize(buf);
  ExpectStr("chaotic_good.header_bytes", Hex(std::string(reinterpret_cast<char*>(buf), sizeof(buf))),
            "a0070000000000000500000064000000");
  auto p = TcpFrameHeader::Parse(buf);
  Report("chaotic_good.header_parse", p.ok() && p->header.type == FrameType::kMessage &&
                                          p->header.stream_id == 5 && p->header.payload_length == 100 &&
                                          p->payload_tag == 7);
  TcpDataFrameHeader d{0x0102, 0x0304, 0x05};
  uint8_t dbuf[TcpDataFrameHeader::kFrameHeaderSize];
  d.Serialize(dbuf);
  ExpectStr("chaotic_good.data_header_bytes", Hex(std::string(reinterpret_cast<char*>(dbuf), sizeof(dbuf))),
            "02010000000000000403000000000000" "05000000");
  auto dp = TcpDataFrameHeader::Parse(dbuf);
  Report("chaotic_good.data_header_parse", dp.ok() && dp->payload_tag == 0x0102 && dp->send_timestamp == 0x0304 &&
                                               dp->payload_length == 5);
}

}  // namespace

int main() {
  grpc_init();
  TestUri();
  TestPercentEncoding();
  TestHuffman();
  TestCompression();
  TestJson();
  TestSockaddr();
  TestHttp();
  TestServiceConfig();
  TestChaoticGood();
  grpc_shutdown();
  printf("SUMMARY pass=%d fail=%d\n", g_pass, g_fail);
  return g_fail == 0 ? 0 : 1;
}
