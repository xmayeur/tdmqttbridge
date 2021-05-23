#!/bin/bash
container=tdmqttbridge
suffix=arm7
if [ -n "$(docker ps -q -f name=$container)" ] ; then
    sudo docker rm -f  $container
fi

sudo docker pull xmayeur/$container:$suffix

sudo docker-compose -f docker-compose-$suffix.yml up -d $container 2>/dev/null
