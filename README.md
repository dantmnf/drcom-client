# drcom-client
for Dr.COM variant
![about](https://user-images.githubusercontent.com/2252500/30239658-3e20747e-9594-11e7-8a97-5227050bfedd.png)

## Why This
- It runs/starts faster than [Python version](https://github.com/drcoms/drcom-generic) on OpenWrt (→_→) ~~（又不是不能用~~
- User experience improvements

## Requirements
PHP modules/extensions:
- sockets
- json (for getting interface information on OpenWrt)
- simplexml (for getting interface information on Windows)
- mbstring (for displaying server-sent messages)
- pcntl (for Ctrl-C to logout)

## Usage
1. Edit `config.php` (refer to [drcom-generic](https://github.com/drcoms/drcom-generic) for configuration, note that some syntax differs)<br/>
If using Windows/OpenWrt, you can use `config-*.php`, which will automatically get some fields from interface name (especially `host_ip`)
2. Run `drcomfucker.php` in PHP CLI SAPI.<br/>
<small>e.g. `php drcomfucker.php` or `php5-cli drcomfucker.php`</small>
