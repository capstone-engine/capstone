#!/usr/bin/bash

python3.11 -m usort format src/autosync
python3.11 -m black src/autosync
