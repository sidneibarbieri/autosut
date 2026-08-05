#!/bin/bash
for adversary_file in data/caldera_adversaries/0.*; do
    python tools/split_campaign.py "$adversary_file"
done
