#!/bin/bash
# CVE-2026-98432 只读自查 + 可选缓解 (在目标 Linux 主机上以 root 运行)
# 用法: bash check-and-mitigate.sh          # 只查, 不改任何东西
#       bash check-and-mitigate.sh mitigate # 查完后关全机 MPTCP 并提示重启服务
set -u
echo "== 运行中内核 (uname -r) =="; uname -r
echo "上游已修版本: 5.10.272 / 5.15.223 / 6.1.190 / 6.6.159 / 6.12.113 / 6.18.56 / 7.2.10 / 7.3"
echo "Debian 已修包: 12 -> 6.1.190-1, 13 -> 6.12.113-1 (装完必须重启进新内核)"
echo
echo "== sysctl =="
sysctl net.mptcp.enabled net.ipv4.tcp_migrate_req 2>&1
echo
echo "== 当前 MPTCP 监听 (ss -lnMp, 空 = 无) =="
ss -lnMp 2>&1
echo
echo "== 全部 TCP 监听 =="
ss -lntp 2>&1 | head -n 40
if [ "${1:-}" = "mitigate" ]; then
  echo
  echo "== 缓解: 全机关闭 MPTCP (只挡新 socket, 已开的监听须重启服务才消失) =="
  sysctl -w net.mptcp.enabled=0
  echo 'net.mptcp.enabled = 0' > /etc/sysctl.d/90-cve-2026-98432.conf
  echo "已持久化 /etc/sysctl.d/90-cve-2026-98432.conf"
  echo "下一步: 重启所有 Go 服务 (caddy/xray/sing-box/v2ray...), 再跑一次本脚本确认 ss -lnMp 为空"
  echo "注意: 这只是缓解, 不是修复 — 底层 UAF 在普通 TCP 上同样存在, 最终必须换已修内核并重启"
  echo "更强的临时封堵 (丢弃所有带 IPv4 头选项的 TCP 包, Red Hat RHSB-2026-016):"
  echo "  nft add table inet cve_2026_98432 '{ chain input { type filter hook input priority -310; policy accept; ip protocol tcp ip hdrlength > 5 counter drop } }'"
fi
