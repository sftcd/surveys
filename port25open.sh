TOTAL=$(wc -l < IE-20250621-223528/input.ips)
OPEN=$(wc -l < IE-20250621-223528/zmap.ips)
CLOSED=$(( TOTAL - OPEN ))

echo "Port 25 开放:   $OPEN"
echo "Port 25 未开放: $CLOSED"
