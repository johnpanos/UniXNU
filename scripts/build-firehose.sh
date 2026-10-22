#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
if [ ! -d .cache/libdispatch-work/.git ]; then
  git clone --shared refer/libdispatch .cache/libdispatch-work
fi
python3 - <<'PY'
from pathlib import Path
p = Path('.cache/libdispatch-work/xcodeconfig/libfirehose_kernel.xcconfig')
s = p.read_text()
s = s.replace('$(SDKROOT)/System/Library/Frameworks/Kernel.framework',
              '$(FAKEROOT_DIR)/System/Library/Frameworks/Kernel.framework')
s = s.replace('$(SDKROOT)/usr/local/include', '$(FAKEROOT_DIR)/usr/local/include')
lines = s.splitlines()
for index, line in enumerate(lines):
    if line.startswith('HEADER_SEARCH_PATHS =') and '$(SDKROOT)/usr/include' not in line:
        lines[index] += (' $(SDKROOT)/usr/include $(FAKEROOT_DIR)/usr/local/include'
                         ' $(PROJECT_DIR)/../xnu-work/EXTERNAL_HEADERS')
s = '\n'.join(lines) + '\n'
if p.read_text() != s:
    p.write_text(s)
PY
if command -v xcodebuild >/dev/null; then
  xcodebuild install -project .cache/libdispatch-work/libdispatch.xcodeproj \
    -target libfirehose_kernel -configuration Release -sdk iphoneos -jobs "${JOBS:-4}" \
    ARCHS=arm64 VALID_ARCHS=arm64 ONLY_ACTIVE_ARCH=NO IPHONEOS_DEPLOYMENT_TARGET="${UNIXNU_XNU_IOS_MIN:-17.0}" \
    CODE_SIGNING_ALLOWED=NO GCC_TREAT_WARNINGS_AS_ERRORS=NO \
    OBJROOT="$ROOT/build/firehose/obj" SYMROOT="$ROOT/build/firehose/sym" \
    DSTROOT="$ROOT/.cache/fakeroot" FAKEROOT_DIR="$ROOT/.cache/fakeroot"
else
  # Hosts without Xcode: the libfirehose_kernel target by hand. Its one source with the flags of
  # libfirehose_kernel.xcconfig and Xcode's Release defaults (-Os, -g), and its one Private header.
  WORK=$ROOT/.cache/libdispatch-work
  FAKEROOT=$ROOT/.cache/fakeroot
  OBJ=$ROOT/build/firehose/obj
  mkdir -p "$OBJ" "$FAKEROOT/usr/local/lib/kernel" "$FAKEROOT/usr/local/include/kernel/os"
  xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min="${UNIXNU_XNU_IOS_MIN:-17.0}" -Os -g -c \
    -mkernel -nostdinc -Wno-packed \
    -DKERNEL=1 -DDISPATCH_USE_DTRACE=0 -DOS_ATOMIC_CONFIG_MEMORY_ORDER_DEPENDENCY=1 \
    -DOS_ATOMIC_CONFIG_STARVATION_FREE_ONLY=0 \
    -I"$WORK" -I"$FAKEROOT/System/Library/Frameworks/Kernel.framework/PrivateHeaders" \
    -I"$FAKEROOT/System/Library/Frameworks/Kernel.framework/Headers" -I"$FAKEROOT/usr/local/include/os" \
    -I"$FAKEROOT/usr/local/include/firehose" -I"$(xcrun -sdk iphoneos --show-sdk-path)/usr/include" \
    -I"$FAKEROOT/usr/local/include" -I"$WORK/../xnu-work/EXTERNAL_HEADERS" \
    "$WORK/src/firehose/firehose_buffer.c" -o "$OBJ/firehose_buffer.o"
  rm -f "$FAKEROOT/usr/local/lib/kernel/libfirehose_kernel.a"
  xcrun ar rcs "$FAKEROOT/usr/local/lib/kernel/libfirehose_kernel.a" "$OBJ/firehose_buffer.o"
  status=0
  unifdef -DKERNEL=1 -DOS_FIREHOSE_SPI=1 -DOS_VOUCHER_ACTIVITY_SPI_TYPES=1 -UOS_VOUCHER_ACTIVITY_SPI \
    -o "$FAKEROOT/usr/local/include/kernel/os/firehose_buffer_private.h" "$WORK/os/firehose_buffer_private.h" || status=$?
  [ "$status" -le 1 ]   # unifdef exits 1 when it changed the file
fi
if [ -f .cache/fakeroot/usr/local/lib/kernel/liblibfirehose_kernel.a ]; then
  cp .cache/fakeroot/usr/local/lib/kernel/liblibfirehose_kernel.a \
    .cache/fakeroot/usr/local/lib/kernel/libfirehose_kernel.a
fi
xcrun lipo -info .cache/fakeroot/usr/local/lib/kernel/libfirehose_kernel.a
