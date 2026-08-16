#!/bin/bash
# live_run.sh — Gate2 真实网络运行（单端启动器）
#
# 用法（两台真实主机各跑一端）：
#   监听端:  live_run.sh listen  <信号端口>  <STUN服务器列表>  [--hold-s 5 --session-out /tmp/live_a.json]
#   连接端:  live_run.sh connect <监听端IP> <信号端口> <STUN服务器列表> [同上]
#
# 示例：
#   host A:  ./live_run.sh listen  9900 stun.l.google.com:19302 --session-out /tmp/live_a.json
#   host B:  ./live_run.sh connect A_PUB_IP 9900 stun.l.google.com:19302 --session-out /tmp/live_b.json
#
# 默认使用 RECOMMENDED_PARAMS.md 推荐参数（N=8 W=2 M=32 pool=1 budget=2s）。
# 输出：session JSON（--session-out）+ stdout 日志（含 NAT profile / 事件时间线）。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PUNCHER="$HERE/puncher.py"

ROLE="${1:?usage: live_run.sh <listen|connect> ...}"; shift

BASE_ARGS=(
  --predict-n 8
  --window-w 2
  --random-m 32
  --pool 1
  --budget-s 2.0
  --filtering-probe
  --hairpin-probe
  --probe-timeout 1.5
  --retry-ms 400
  --window-s 8
)

if [ "$ROLE" = "listen" ]; then
  PORT="${1:?listen: <signal-port>}"; shift
  STUN="${1:?listen: <stun servers>}"; shift
  exec python3 "$PUNCHER" --role listen --port "$PORT" --stun "$STUN" \
    "${BASE_ARGS[@]}" "$@"
elif [ "$ROLE" = "connect" ]; then
  HOST="${1:?connect: <listen host ip>}"; shift
  PORT="${1:?connect: <signal-port>}"; shift
  STUN="${1:?connect: <stun servers>}"; shift
  exec python3 "$PUNCHER" --role connect --host "$HOST" --port "$PORT" --stun "$STUN" \
    "${BASE_ARGS[@]}" "$@"
else
  echo "role must be listen|connect" >&2
  exit 2
fi