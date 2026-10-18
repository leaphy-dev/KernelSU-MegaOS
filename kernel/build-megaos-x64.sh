#!/bin/bash
# ============================================================================
# build-megaos-x64.sh — H3C MegaBook / MegaOS (Android 14, kernel 6.12.30) LKM 构建
#
# 这是 H3C MegaBook 14 的专用构建入口（对应上游 kernel/build-all-x64.sh 的位置），
# 与上游构建脚本的差异（每一条都对应一个实际踩过的坑）：
#   1) 内核树用 ACK 树（KDIR，默认 ~/megabook/ack），不是 DDK 的 /opt/ddk
#   2) 跳过上游的 check_symbol：H3C MegaBook 14 KALLSYMS_ALL=n 且 vmlinux 无 __crc_*，
#      符号校验必然失败；改用 shim + 运行期解析
#   3) 每次构建前清除产物：系统时钟错乱会产生"未来时间戳"，
#      导致 make 跳过 `LD [M] kernelsu.o`，产物静默不变
#   4) 构建后把 __versions 段 sh_size 清零（保留段）：MODVERSIONS=y 会做
#      CRC 比对，H3C MegaBook 14 没有 __crc_* ⇒ 不清零则 insmod 直接失败
#
# 用法：
#   ./build-megaos-x64.sh                     # 默认：persistent 日志开，无 panic 转储
#   ./build-megaos-x64.sh --no-persist-log    # 关闭 KSU_X86_PERSISTENT_BOOT_LOG（no-op）
#   ./build-megaos-x64.sh --diag              # 打开 KSU_X86_BLACKBOX（panic 转储）
#   ./build-megaos-x64.sh --out /tmp/kernelsu.ko
#   KDIR=/path/to/kernel ./build-megaos-x64.sh
# ============================================================================
set -euo pipefail

MDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ODIR=${ODIR:-$MDIR}
KDIR=${KDIR:-$HOME/megabook/ack}

DIAG=0
PERSIST_LOG=1
OUT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --diag)             DIAG=1 ;;
        --persist-log)      PERSIST_LOG=1 ;;
        --no-persist-log)   PERSIST_LOG=0 ;;
        --out)              OUT="${2:-}"; shift ;;
        -h|--help)    sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

FLAGS="-DKSU_X86_SKIP_SYMBOL_RESOLVER_INIT -DKSU_X86_PATCH_VIA_SETMEMORY2"
[ "$PERSIST_LOG" = 1 ] && FLAGS="$FLAGS -DKSU_X86_PERSISTENT_BOOT_LOG"
[ "$DIAG" = 1 ] && FLAGS="$FLAGS -DKSU_X86_BLACKBOX"

export ARCH=x86_64 LLVM=1 LLVM_IAS=1

echo "=== configuration ==="
echo "  MDIR  : $MDIR"
echo "  ODIR  : $ODIR"
echo "  KDIR  : $KDIR"
echo "  FLAGS : $FLAGS"

echo
echo "=== clock/future-mtime check ==="
NOW=$(date '+%Y-%m-%d %H:%M:%S')
FUTURE=$(find "$ODIR" \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '.*.cmd' \) \
              -newermt "$NOW" 2>/dev/null | wc -l)
echo "  future-dated artifacts: $FUTURE"
[ "$FUTURE" -gt 0 ] && echo "  WARNING: future timestamps detected (clock skewed?)"

echo
echo "=== purge build artifacts (force composite relink) ==="
cd "$ODIR"
find . \( -name '*.o' -o -name '*.ko' -o -name '*.mod' -o -name '*.mod.c' -o -name '.*.cmd' \) -delete 2>/dev/null || true
rm -f modules.order Module.symvers .modules.order.cmd
echo "  remaining .o: $(find . -name '*.o' | wc -l)"

echo
echo "=== build ==="
BUILD_LOG=$(mktemp)
# dispatcher
if ! make -C "$KDIR" M="$ODIR" src="$MDIR" modules \
        CONFIG_KSU=m CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER=y \
        KCFLAGS="$FLAGS" -j"$(nproc)" >"$BUILD_LOG" 2>&1; then
    echo "  BUILD FAILED:"
    grep -E 'error:|Error [0-9]' "$BUILD_LOG" | head -20
    rm -f "$BUILD_LOG"
    exit 1
fi
grep -E 'CC \[M\].*/syscall_hook|LD \[M\]' "$BUILD_LOG" | sed 's/^/  /'

# 复合链接必须执行过（时钟错乱时这里会静默跳过，产物不变）
if ! grep -q 'LD \[M\].*/kernelsu\.o' "$BUILD_LOG"; then
    echo "  ERROR: composite link (LD [M] kernelsu.o) did not run - artifact is stale"
    rm -f "$BUILD_LOG"
    exit 1
fi
echo "  composite link executed: OK"
rm -f "$BUILD_LOG"

echo
echo "=== zero __versions (MODVERSIONS=y requires sh_size=0, keep the section) ==="
python3 - "$ODIR/kernelsu.ko" <<'PY'
import struct, sys
p = sys.argv[1]
d = bytearray(open(p, 'rb').read())
shoff  = struct.unpack_from('<Q', d, 0x28)[0]
ent    = struct.unpack_from('<H', d, 0x3a)[0]
n      = struct.unpack_from('<H', d, 0x3c)[0]
si     = struct.unpack_from('<H', d, 0x3e)[0]
strtab = struct.unpack_from('<Q', d, shoff + si * ent + 0x18)[0]
for i in range(n):
    o  = shoff + i * ent
    no = struct.unpack_from('<I', d, o)[0]
    e  = d.index(b'\x00', strtab + no)
    if d[strtab + no:e] == b'__versions':
        struct.pack_into('<Q', d, o + 0x20, 0)   # sh_size = 0
        break
open(p, 'wb').write(bytes(d))
print("  __versions -> sh_size = 0")
PY

echo
echo "=== verify ==="
[ -f kernelsu.ko ] || { echo "  no artifact"; exit 1; }

VER=$(readelf -SW kernelsu.ko | awk '/__versions/{print $6}')
[ "$VER" = "000000" ] && echo "  __versions = 000000: OK" || echo "  __versions = $VER: BAD"

SRC=hook/x86_64/syscall_hook.c
[ kernelsu.ko -nt "$SRC" ] && echo "  artifact newer than source: OK" || echo "  artifact OLDER than source: BAD"

UNDS=$(readelf -sW kernelsu.ko | awk '$7=="UND"{print $8}' | sort -u)
echo "  UND symbols         : $(echo "$UNDS" | wc -l)"
echo "  module_alloc (0 req) : $(echo "$UNDS" | grep -c '^module_alloc$')"
echo "  set_memory_x         : $(echo "$UNDS" | grep -c '^set_memory_x$')"
echo "  vmalloc_noprof       : $(echo "$UNDS" | grep -c '^vmalloc_noprof$')"
echo "  sha256               : $(sha256sum kernelsu.ko | awk '{print $1}')"
echo "  size                 : $(stat -c%s kernelsu.ko) B"

if [ -n "$OUT" ]; then
    cp kernelsu.ko "$OUT"
    echo "  copied to: $OUT"
fi
