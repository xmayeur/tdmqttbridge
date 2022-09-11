NAME="tdmqttbridge"
docker rm -f $NAME
# docker run --rm --privileged multiarch/qemu-user-static:register --reset
docker build -t $NAME -f Dockerfile-arm7 .
docker tag $NAME xmayeur/$NAME
docker push xmayeur/$NAME
docker run -it --name $NAME --network=host  --restart always xmayeur/$NAME

