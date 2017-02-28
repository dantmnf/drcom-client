# drcom-client
for DHCP variant

## Why This
- It runs/starts faster than [Python version](https://github.com/drcoms/drcom-generic) on OpenWrt (→_→) ~~（又不是不能用~~
- User experience improvements

## Requirements
PHP modules/extensions:
- sockets
- json (for getting interface information on OpenWrt)
- mbstring (for displaying server-sent messages)
- pcntl (for Ctrl-C to logout)