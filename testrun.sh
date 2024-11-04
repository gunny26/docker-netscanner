#!/bin/bash
export APP_REDIS_HOST=redis-lmp.messner.click
export APP_INTERFACE=wlp4s0
# python3 -m profile build/main.py
python3 build/main.py

