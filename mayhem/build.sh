#!/usr/bin/env bash
#
# mayhem/build.sh — builds gRPC core with $SANITIZER_FLAGS (+ fuzzer-no-link coverage), the libFuzzer harnesses and
# their -standalone reproducers, and an unsanitized known-answer self-test for mayhem/test.sh.
# Offline: every dependency (abseil, boringssl, c-ares, re2, zlib, protobuf, upb) comes from the git submodules the
# Dockerfile checked out; nothing is fetched here.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${COVERAGE_FLAGS=}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE COVERAGE_FLAGS

cd "${SRC:-/mayhem}"
SRC="$(pwd)"

# gRPC's sanitized C++ compiles peak around 1.5 GiB each: cap -j by the memory the container actually has.
mem_kb="$(awk '/MemTotal/{print $2}' /proc/meminfo)"
if [ -r /sys/fs/cgroup/memory.max ] && [ "$(cat /sys/fs/cgroup/memory.max)" != max ]; then
  mem_kb=$(( $(cat /sys/fs/cgroup/memory.max) / 1024 ))
fi
mem_jobs=$(( mem_kb / 1572864 )); [ "$mem_jobs" -ge 1 ] || mem_jobs=1
: "${MAYHEM_JOBS:=$(nproc)}"
[ "$MAYHEM_JOBS" -le "$mem_jobs" ] || MAYHEM_JOBS="$mem_jobs"

for m in third_party/abseil-cpp third_party/boringssl-with-bazel third_party/cares/cares third_party/re2 \
         third_party/zlib third_party/protobuf; do
  [ -e "$m/CMakeLists.txt" ] || { echo "submodule $m missing (the Dockerfile fetches it)" >&2; exit 1; }
done

CMAKE_COMMON=(-G Ninja -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" -DCMAKE_CXX_STANDARD=17
  -DgRPC_BUILD_TESTS=OFF -DgRPC_BUILD_CODEGEN=OFF -DgRPC_BUILD_CSHARP_EXT=OFF -DgRPC_DOWNLOAD_ARCHIVES=OFF
  -DgRPC_ABSL_PROVIDER=module -DgRPC_CARES_PROVIDER=module -DgRPC_PROTOBUF_PROVIDER=module
  -DgRPC_RE2_PROVIDER=module -DgRPC_SSL_PROVIDER=module -DgRPC_ZLIB_PROVIDER=module
  -DBUILD_SHARED_LIBS=OFF)

# 0) The normal-flags build: the known-answer self-test (step 3) links it, and its protoc (from the same protobuf
#    submodule as the sanitized libprotobuf) generates the chaotic-good frame protos the frame harness compiles.
cmake -S . -B mayhem/build/test "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build mayhem/build/test --target grpc gpr protoc -j"$MAYHEM_JOBS"
PROTOC="$(find mayhem/build/test -name protoc -perm -u+x | head -n1)"
[ -n "$PROTOC" ] || { echo "protoc was not built" >&2; exit 1; }
GEN=mayhem/build/gen
mkdir -p "$GEN"
"$PROTOC" -I . --cpp_out="$GEN" src/core/ext/transport/chaotic_good/chaotic_good_frame.proto

# 1) The sanitized core library. fuzzer-no-link puts SanCov edge counters on the fuzzed code itself.
FUZZ_FLAGS="-O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
cmake -S . -B mayhem/build/fuzz "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS"
cmake --build mayhem/build/fuzz --target grpc gpr libprotobuf -j"$MAYHEM_JOBS"

# 2) Harnesses: one libFuzzer binary and one -standalone reproducer each.
includes() {  # $1 = cmake build dir (holds the generated zlib/cares headers)
  printf '%s\n' -I"$SRC" -I"$SRC/include" -I"$SRC/third_party/abseil-cpp" -I"$SRC/third_party/address_sorting/include" \
    -I"$SRC/third_party/boringssl-with-bazel/include" -I"$SRC/src/core/ext/upb-gen" -I"$SRC/src/core/ext/upbdefs-gen" \
    -I"$SRC/third_party/upb" -I"$SRC/third_party/utf8_range" -I"$SRC/third_party/xxhash" \
    -I"$SRC/third_party/re2" -I"$SRC/third_party/protobuf/src" -I"$SRC/mayhem/build/gen" -I"$SRC/third_party/zlib" -I"$SRC/$1/third_party/zlib" \
    -I"$SRC/third_party/cares/cares/include" -I"$SRC/$1/third_party/cares/cares"
}
mapfile -t INCLUDES < <(includes mayhem/build/fuzz)
mapfile -t LIBS < <(find mayhem/build/fuzz -name '*.a' | sort)
LINK=(-Wl,--start-group "${LIBS[@]/#/$SRC/}" -Wl,--end-group -lpthread -ldl -lm)
HCXX=(-std=c++17 -O1 $SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -D_LARGEFILE64_SOURCE=1)

mkdir -p mayhem/build/obj
$CXX "${HCXX[@]}" -c mayhem/lsan_off.cc -o mayhem/build/obj/lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o mayhem/build/obj/standalone_main.o

TARGETS=(fuzz_uri_parse fuzz_percent_encoding fuzz_huffman fuzz_message_decompress fuzz_hpack_parser
         fuzz_json_parse fuzz_sockaddr_parse fuzz_http_parser fuzz_service_config fuzz_chaotic_good_frame_header)

# The chaotic-good transport is not part of the CMake libgrpc, so its framing codec (headers, frame.cc and the
# protoc-generated message classes) is compiled into that harness.
extra_sources() {
  case "$1" in
    fuzz_chaotic_good_frame_header)
      echo src/core/ext/transport/chaotic_good/tcp_frame_header.cc src/core/ext/transport/chaotic_good/frame_header.cc \
           src/core/ext/transport/chaotic_good/frame.cc \
           mayhem/build/gen/src/core/ext/transport/chaotic_good/chaotic_good_frame.pb.cc ;;
  esac
}

build_harness() {
  local t="$1" objs=("mayhem/build/obj/$t.o") src
  $CXX "${HCXX[@]}" "${INCLUDES[@]}" -c "mayhem/$t.cc" -o "mayhem/build/obj/$t.o"
  for src in $(extra_sources "$t"); do
    $CXX "${HCXX[@]}" "${INCLUDES[@]}" -c "$src" -o "mayhem/build/obj/$t.$(basename "$src" .cc).o"
    objs+=("mayhem/build/obj/$t.$(basename "$src" .cc).o")
  done
  $CXX "${HCXX[@]}" $LIB_FUZZING_ENGINE "${objs[@]}" mayhem/build/obj/lsan_off.o "${LINK[@]}" -o "/mayhem/$t"
  $CXX "${HCXX[@]}" "${objs[@]}" mayhem/build/obj/lsan_off.o mayhem/build/obj/standalone_main.o "${LINK[@]}" \
    -o "/mayhem/$t-standalone"
}
PIDS=()
for t in "${TARGETS[@]}"; do
  while [ "$(jobs -rp | wc -l)" -ge "$MAYHEM_JOBS" ]; do wait -n || true; done
  build_harness "$t" & PIDS+=($!)
done
for i in "${!PIDS[@]}"; do
  wait "${PIDS[$i]}" || { echo "harness ${TARGETS[$i]} failed to build" >&2; exit 1; }
done

# 3) Known-answer self-test against the NORMAL-flags build of the same library (step 0).
mapfile -t TLIBS < <(find mayhem/build/test -name '*.a' | sort)
$CXX -std=c++17 $COVERAGE_FLAGS -D_LARGEFILE64_SOURCE=1 $(includes mayhem/build/test) \
  mayhem/selftest.cc src/core/ext/transport/chaotic_good/tcp_frame_header.cc \
  src/core/ext/transport/chaotic_good/frame_header.cc -Wl,--start-group "${TLIBS[@]/#/$SRC/}" -Wl,--end-group -lpthread -ldl -lm \
  -o /mayhem/grpc_selftest
