@echo off

echo opening multiple curl request throgh the tor client:
curl --socks5 127.0.0.1:1080 https://google.com &
curl --socks4 127.0.0.1:1080 http://ipinfo.io &
curl --socks5 127.0.0.1:1080 https://xkcd.com/info.0.json &
curl --socks5 127.0.0.1:1080 https://opentdb.com/api.php?amount=1

pause