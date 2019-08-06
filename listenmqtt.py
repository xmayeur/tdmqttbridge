import paho.mqtt.client as mqtt
import sys
from time import sleep, time, strftime


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("connected ok")
        client.connected_flag = True


def on_message(client, userdata, message):
    _topic = message.topic
    msg = str(message.payload.decode('utf-8'))
    print('Received message: ' + _topic + '/' + msg)


mqtt.Client.connected_flag = False
# Connect to mqtt bus

host = '192.168.0.4'  #  'test.mosquitto.org'
project = 'xma'

uname, pwd = 'IoT', 'Bretzel58'
client = mqtt.Client(project)
client.username_pw_set(username=uname, password=pwd)
client.on_connect = on_connect
client.on_message = on_message
duration = 5
client.connect(host, port=1883)
client.subscribe('#')
client.loop_start()
client.subscribe(project + '/getStatus')



while True:
    # Get device list ans state
    topic = 'getStatus'
    value = strftime('%x')
    client.publish(project + '/' + topic, value, qos=0, retain=False)
    print('.', end='')
    sys.stdout.flush()
    sleep(duration)

