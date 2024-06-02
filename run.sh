#!/bin/bash
docker compose up -d

sleep 4
docker exec -d  ue1 bash -c  "nr-ue --config uecfg.yaml &> ./ue1log.txt"
sleep 3
docker exec ue1 cat ./ue1log.txt > ./logs/ue1log.txt

sleep 4
# docker exec -d  ue2 bash -c  "nr-ue --config uecfg.yaml &> ./ue2log.txt"
# sleep 3
# docker exec ue2 cat ./ue2log.txt > ./logs/ue2log.txt

docker logs amf1 &> ./logs/amf1log.txt
sleep 4

docker compose down


echo "========================================LOG UE1==============================="
cat ./logs/ue1log.txt
# echo "========================================LOG UE2==============================="
# cat ./logs/ue2log.txt
echo "========================================LOG AMF1=============================="
cat ./logs/amf1log.txt