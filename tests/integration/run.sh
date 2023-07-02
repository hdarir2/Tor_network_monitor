#!/bin/bash
# Instead of exiting inmmediately when any of this commands fail,
# the scanner, generate and coverage lines could continue and store there was
# an error on that command. It's just simpler with `-e`.
set -ex

tests/integration/start_chutney.sh
python3 scripts/tools/sbws-http-server.py --port 28888 &>/dev/null &
sleep 1
wget -O/dev/null http://127.0.0.1:28888/sbws.bin
# Run actually the scanner
sbws -c tests/integration/sbws_testnet.ini scanner
sbws -c tests/integration/sbws_testnet.ini generate
# Run integration tests
coverage run -a --rcfile=.coveragerc --source=sbws -m pytest -s tests/integration -vv
sbws -c tests/integration/sbws_testnet.ini cleanup
tests/integration/stop_chutney.sh
