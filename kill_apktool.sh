#!/bin/bash

# 查找正在运行的apktool进程
pid=$(ps aux | grep apktool | grep -v grep | awk '{print $2}')

# 如果找到了apktool进程，杀掉它
if [ -n "$pid" ]; then
    kill $pid
    echo "Killed apktool process with PID $pid."
else
    echo "No apktool process found."
fi

