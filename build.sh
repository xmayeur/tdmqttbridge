NAME="tdmqttbridge"
docker rm -f $NAME
docker run --rm --privileged multiarch/qemu-user-static:register --reset
docker build -t $NAME .
docker tag $NAME xmayeur/$NAME
docker run -it --name $NAME --network=host  --restart always xmayeur/$NAME

