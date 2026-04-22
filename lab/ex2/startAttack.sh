#!/bin/bash

cp modified-krack-test-client.py ./krackattacks-script/krackattack/
cd ./krackattacks-scripts/krackattack
source venv/bin/activate;
python3 modified-krack-test-client.py --debug;