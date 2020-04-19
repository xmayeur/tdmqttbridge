#!/bin/bash
container=tdmqttbridge
suffix=-x86
if [ -n "$(docker ps -q -f name=$container)" ] ; then
    sudo docker rm -f  $container
fi

sudo docker pull xmayeur/$container$suffix

sudo docker-compose -f docker-compose-x86.yml --force-recreate up -d $container