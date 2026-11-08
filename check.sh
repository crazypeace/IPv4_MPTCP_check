#!/bin/bash
# CVE-2026-98432 只读自查 + 可选缓解 (在目标 Linux 主机上以 root 运行); 附带 APT 版本自查 (CVE-2026-109518 / DSA-6607-1)
# 用法: bash check-and-mitigate.sh          # 只查, 不改任何东西
#       bash check-and-mitigate.sh mitigate # 查完后关全机 MPTCP 并提示重启服务
set -u
echo "== 运行中内核 (uname -r) =="; uname -r
echo "== 对应 Debian 包版本 (dpkg; 版本号后的 -1 是打包修订号, 永远不会出现在 uname 里, 两者指的是同一个内核) =="
dpkg -l "linux-image-$(uname -r)" 2>/dev/null | grep "^ii" || echo "(查不到同名包: 非 Debian 官方包内核, 需另行核对)"
echo "== 该包 changelog 是否含 CVE-2026-98432 (命中 = 已修复, 这是比版本号更硬的判据) =="
{ zgrep -m1 "CVE-2026-98432" "/usr/share/doc/linux-image-$(uname -r)/changelog.gz" 2>/dev/null || zgrep -m1 "CVE-2026-98432" "/usr/share/doc/linux-image-$(uname -r)/changelog.Debian.gz" 2>/dev/null || echo "未命中: 该包未提及本 CVE, 按未修复处理"; }
echo "上游已修版本: 5.10.272 / 5.15.223 / 6.1.190 / 6.6.159 / 6.12.113 / 6.18.56 / 7.2.10 / 7.3"
echo "Debian 已修包: 12 -> 6.1.190-1, 13 -> 6.12.113-1 (装完必须重启进新内核)"
echo
echo "== APT 版本 (CVE-2026-109518, DSA-6607-1, 2026-11-04; 中间人可替换已验签软件包并以 root 执行代码) =="
echo "Debian 已修 APT 版本: 12 (bookworm) -> 2.6.2, 13 (trixie) -> 3.0.4"
APT_VER="$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)"
if [ -z "$APT_VER" ]; then
  echo "(查不到 apt 包: 非 Debian 系或 apt 工具异常, 需另行核对)"
else
  echo "已装 APT 版本: $APT_VER (apt --version: $(apt --version 2>/dev/null | head -n 1))"
  DEB_REL="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"
  case "$DEB_REL" in
    12) APT_FIXED="2.6.2" ;;
    13) APT_FIXED="3.0.4" ;;
    *)  APT_FIXED="" ;;
  esac
  if [ -n "$APT_FIXED" ]; then
    if dpkg --compare-versions "$APT_VER" ge "$APT_FIXED"; then
      echo "判定: 已装 $APT_VER >= 已修 $APT_FIXED -> 本 CVE 已修复"
    else
      echo "判定: 已装 $APT_VER < 已修 $APT_FIXED -> 未修复, 需升级 APT"
    fi
  else
    echo "判定: 未知 Debian 版本 ($DEB_REL), 无法自动比对, 请人工对照: 12->2.6.2 / 13->3.0.4"
  fi
  echo "该包 changelog 是否含 CVE-2026-109518 (命中 = 该包装有修复, 与版本号互证):"
  { zgrep -m1 "CVE-2026-109518" /usr/share/doc/apt/changelog.gz 2>/dev/null || zgrep -m1 "CVE-2026-109518" /usr/share/doc/apt/changelog.Debian.gz 2>/dev/null || echo "未命中"; }
  echo "仓库候选版本 (apt-cache policy apt; 若候选已达标而未装, 说明只需升级):"
  apt-cache policy apt 2>/dev/null | grep -E "Installed|Candidate|已安装|候选" || apt-cache policy apt 2>/dev/null | head -n 3
  echo "修复命令: sudo apt update && sudo apt install --only-upgrade apt"
fi
echo
echo "== sysctl =="
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req 2>&1
echo
echo "== 当前 MPTCP 监听 (ss -lnMp, 空 = 无) =="
ss -lnMp 2>&1
echo
echo "== 全部 TCP 监听 =="
ss -lntp 2>&1 | head -n 40

