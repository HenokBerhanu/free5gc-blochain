#!/bin/bash
docker compose up -d
sleep 3
docker exec -d  ue1 bash -c  "nr-ue --config uecfg.yaml &> ./uelog.txt"
sleep 2
docker exec ue1 cat ./uelog.txt > ./logs/uelog.txt
docker logs amf1 &> ./logs/amflog.txt
docker compose down
echo "========================================LOG UE==============================="
cat ./logs/uelog.txt
echo "========================================LOG AMF=============================="
cat ./logs/amflog.txt