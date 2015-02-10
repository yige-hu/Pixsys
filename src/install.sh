#!/bin/bash 
set -x
make runme_user
make patcher_root
cp runme_user patcher_root ../attack || echo "FAILED TO MOVE RUNME"

cd ../Hooker
make 

cp hook.ko ../attack

echo "run runme from attack folder"
