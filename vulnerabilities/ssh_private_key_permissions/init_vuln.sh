#!/bin/sh
ssh-keygen -b 2048 -t rsa -f /home/{mainUser}/.ssh/id_rsa -q -N "";chmod 707 /home/{mainUser}/.ssh/id_rsa