# -*- coding: utf-8 -*-
import getopt
import json
import logging
import sys
from logging.handlers import RotatingFileHandler
from time import sleep, localtime, asctime

import oyaml
import paho.mqtt.client as mqtt
import redis
import requests
from requests_oauthlib import OAuth1
from six.moves.urllib.parse import urlencode

project = 'tdMQTTbridge'
LOG_file = project + '.log'
INI_file = project + '.conf'
connect_flag = False

devices = []


def open_log(name):
    # Setup the log handlers to stdout and file.
    log_ = logging.getLogger(name)
    log_.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
    )
    handler_stdout = logging.StreamHandler(sys.stdout)
    handler_stdout.setLevel(logging.DEBUG)
    handler_stdout.setFormatter(formatter)
    log_.addHandler(handler_stdout)
    handler_file = RotatingFileHandler(
        LOG_file,
        mode='a',
        maxBytes=200000,
        backupCount=9,
        encoding='UTF-8',
        delay=True
    )
    handler_file.setLevel(logging.DEBUG)
    handler_file.setFormatter(formatter)
    log_.addHandler(handler_file)
    return log_


log = open_log(project)

# Open config file
try:
    config = oyaml.load(open(INI_file, 'r'), Loader=oyaml.Loader)
except IOError:
    log.critical('configuration file is missing')
    config = None
    exit(-1)


def get_vault(uid):
    global config
    host = config['redis']['host']
    port = config['redis']['port']
    vaultdb = config['redis']['vaultdb']
    vault = redis.Redis(host=host, port=port, db=vaultdb)
    _s = vault.get(uid)
    _id = json.loads(_s)
    if id:
        _username = _id['username']
        _password = _id['password']
    else:
        _username = ''
        _password = ''
    return _username, _password


verbose = config['mqtt']['verbose']

telldus_key = config['telldus']['client']
telldus_apptoken = config['telldus']['token']
PUBLIC_KEY, PRIVATE_KEY = get_vault(telldus_key)
TOKEN, TOKEN_SECRET = get_vault(telldus_apptoken)

TELLSTICK_TURNON = 1
TELLSTICK_TURNOFF = 2
TELLSTICK_BELL = 4
TELLSTICK_DIM = 16
TELLSTICK_UP = 128
TELLSTICK_DOWN = 256

RASPI_ID = 274164
SALON_ID = 223659
SAM_ID = 223659
NAS_ID = 274165

SUPPORTED_METHODS = TELLSTICK_TURNON | TELLSTICK_TURNOFF | TELLSTICK_BELL | TELLSTICK_DIM | TELLSTICK_UP | TELLSTICK_DOWN


def do_mqtt_connect(client, host, port):
    global connect_flag
    try:
        client.connect(host, port=port)
        while not client.connected_flag:
            print('+', end='')
            sys.stdout.flush()
            sleep(1)
    # except mqtt.MQTT_ERR_ACL_DENIED:
    #     print('Invalid username or password')
    #     log.critical('Invalid username or password')
    
    except Exception as e:
        print('Cannot connect to mqtt broker -  error: ' + str(e))
        log.critical('Cannot connect to mqtt broker - retrying')
        client.connected_flag = False


def do_mqtt_publish(client, key, value, qos=2, retain=False):
    try:
        client.publish(project + '/' + key, str(value), qos=0, retain=False)
        return True
    except Exception as e:
        print('Cannot publish to mqtt broker -  error: ' + str(e))
        log.critical('Cannot publish to mqtt broker - retrying')
        return False


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        if verbose:
            print("connected ok")
        client.connected_flag = True
        # subscribe after connection OK
        do_subscribe(client)
    else:
        log.info('mqtt on_connect return code is: ' + str(rc))


def on_message(client, userdata, message):
    global verbose
    topic = message.topic
    msg = str(message.payload.decode('utf-8'))
    print('Received message: ' + topic + '/' + msg)
    sys.stdout.flush()
    if topic == project + '/getStatus':
        do_mqtt_publish(client, project + '/status', 'alive', qos=0, retain=False)
    elif 'setValue' in topic:
        r = do_methodByName(topic.split('/')[1], msg)
        sleep(1)
        publishDevices(client)
        if verbose:
            print('setValue - doMethod return ' + str(r))
            sys.stdout.flush()
    elif topic == project + '/getDevices':
        publishDevices(client)
        publishSensors(client)
    elif 'verbose' in topic:
        if msg == '1':
            verbose = True
        else:
            verbose = False
    client.on_message = on_message


def listDevices():
    response = doRequest('devices/list', {'supportedMethods': SUPPORTED_METHODS})
    # print("Number of devices: %i" % len(response['device']))
    for device in response['device']:
        if device['state'] == TELLSTICK_TURNON:
            state = 'ON'
        elif device['state'] == TELLSTICK_TURNOFF:
            state = 'OFF'
        elif device['state'] == TELLSTICK_DIM:
            state = "DIMMED"
        elif device['state'] == TELLSTICK_UP:
            state = "UP"
        elif device['state'] == TELLSTICK_DOWN:
            state = "DOWN"
        else:
            state = 'Unknown state'
        # print ("%s\t%s\t%s" % (device['id'], device['name'], state))
    # return json.dumps(response['device'], indent=4, separators=(',', ': '))
    return response['device']


def publishSensors(client):
    response = doRequest('sensors/list', {'includeIgnored': 0})
    # print("Number of sensors: %i" % len(response['sensor']))
    for sensor in response['sensor']:
        detail = doRequest('sensor/info', {'id': sensor['id']})
        r = do_mqtt_publish(client, sensor['name'], json.dumps(detail), qos=0, retain=False)
        # print ("%s\t%s\t%s" % (sensor['id'], sensor['name'], state))
        if not r:
            return False
        data = detail['data']
        for d in data:
            do_mqtt_publish(client, sensor['name'] + '/' + d['name'] + '/value', d['value'])
            lasttime = asctime(localtime(d['lastUpdated']))
            do_mqtt_publish(client, sensor['name'] + '/' + d['name'] + '/lastUpdated', lasttime)
            if verbose:
                print("%s\t%s:\t%s\t%s" % (sensor['name'], d['name'], d['value'], lasttime))
    return True


def publishDevices(client):
    response = doRequest('devices/list', {'supportedMethods': SUPPORTED_METHODS})
    # print("Number of devices: %i" % len(response['device']))
    
    for device in response['device']:
        r = do_mqtt_publish(client, device['name'], json.dumps(device), qos=0, retain=False)
        # print ("%s\t%s\t%s" % (device['id'], device['name'], ''))
        if not r:
            return False
        # publish details
        do_mqtt_publish(client, device['name'] + '/state', str(device['state']))
        if device['state'] == TELLSTICK_DIM:
            do_mqtt_publish(client, device['name'] + '/value', str(100 * int(device['statevalue']) / 255))
        elif device['state'] == TELLSTICK_TURNON:
            do_mqtt_publish(client, device['name'] + '/value', '100')
        elif device['state'] == TELLSTICK_TURNOFF:
            do_mqtt_publish(client, device['name'] + '/value', '0')
        else:
            do_mqtt_publish(client, device['name'] + '/value', '0')
        if verbose:
            print("%s\t%s\t%s" % (device['name'], device['state'], device['statevalue']))
    return True


def getDeviceState(deviceID):
    response = doRequest('device/info', {'id': deviceID, 'supportedMethods': 255})
    val = int(response['state'])
    val2 = str(response['statevalue'])
    
    if val == TELLSTICK_TURNON:
        state = 'ON'
    elif val == TELLSTICK_TURNOFF:
        state = 'OFF'
    elif val == TELLSTICK_DIM:
        state = val2
    elif val == TELLSTICK_UP:
        state = "UP"
    elif val == TELLSTICK_DOWN:
        state = "DOWN"
    else:
        state = 'Unknown state'
    return state


def switchRpiOff():
    doMethod(SALON_ID, TELLSTICK_TURNOFF)


def do_methodByName(deviceName, value):
    global devices
    # d = next((x for x in devices if x.name == deviceName), None)
    d = None
    for d in devices:
        if d['name'] == deviceName:
            break
    if d is not None:
        methodValue = 0
        if value == '100':
            methodId = TELLSTICK_TURNON
        elif value == '0':
            methodId = TELLSTICK_TURNOFF
        else:
            methodId = TELLSTICK_DIM
            methodValue = int(round(255 * int(value) / 100))

        return doMethod(d['id'], methodId, methodValue)


def doMethod(deviceId, methodId, methodValue=0):
    response = doRequest('device/info', {'id': deviceId})
    
    if methodId == TELLSTICK_TURNON:
        method = 'on'
    elif methodId == TELLSTICK_TURNOFF:
        method = 'off'
    elif methodId == TELLSTICK_BELL:
        method = 'bell'
    elif methodId == TELLSTICK_UP:
        method = 'up'
    elif methodId == TELLSTICK_DOWN:
        method = 'down'
    elif methodId == TELLSTICK_DIM:
        method = 'dim'
    
    if 'error' in response:
        name = ''
        retString = response['error']
    else:
        name = response['name']
        response = doRequest('device/command', {'id': deviceId, 'method': methodId, 'value': methodValue})
        if 'error' in response:
            retString = response['error']
        else:
            retString = response['status']
    
    if methodId in (TELLSTICK_TURNON, TELLSTICK_TURNOFF):
        # print ("Turning %s device %s, %s - %s" % (method, deviceId, name, retString))
        return retString
    elif methodId in (TELLSTICK_BELL, TELLSTICK_UP, TELLSTICK_DOWN):
        # print("Sending %s to: %s %s - %s" % (method, deviceId, name, retString))
        return retString
    elif methodId == TELLSTICK_DIM:
        # print ("Dimming device: %s %s to %s - %s" % (deviceId, name, methodValue, retString))
        return retString


def doRequest(method, params):
    try:
        http_url = "http://api.telldus.com/json/" + method + "?" + urlencode(params, True).replace('+', '%20')
        oauth = OAuth1(PUBLIC_KEY, PRIVATE_KEY, TOKEN, TOKEN_SECRET)
        r = requests.get(http_url, auth=oauth)
        return r.json()
    except Exception as e:
        log.critical('Error connecting to Telldus server: ' + str(e))
        response = None


def requestToken():
    return
    # global config
    #
    # consumer = oauth.Consumer(PUBLIC_KEY, PRIVATE_KEY)
    # request = oauth.Request.from_consumer_and_token(consumer, http_url='http://api.telldus.com/oauth/requestToken')
    # request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
    # conn = http.client.HTTPConnection('api.telldus.com:80')
    # conn.request(request.http_method, '/oauth/requestToken', headers=request.to_header())
    #
    # resp = conn.getresponse().read()
    # token = oauth.Token.from_string(resp)
    # print((
    #     'Open the following url in your webbrowser:\nhttp://api.telldus.com/oauth/authorize?oauth_token=%s\n' % token.key))
    # print(('After logging in and accepting to use this application run:\n%s --authenticate' % (sys.argv[0])))
    # config['telldus']['requestToken'] = str(token.key)
    # config['telldus']['requestTokenSecret'] = str(token.secret)
    # saveConfig()


def getAccessToken():
    return
    # global config
    # consumer = oauth.Consumer(PUBLIC_KEY, PRIVATE_KEY)
    # token = oauth.Token(config['telldus']['requestToken'], config['telldus']['requestTokenSecret'])
    # request = oauth.Request.from_consumer_and_token(consumer, token=token, http_method='GET',
    #                                                 http_url='http://api.telldus.com/oauth/accessToken')
    # request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, token)
    # conn = http.client.HTTPConnection('api.telldus.com:80')
    # conn.request(request.http_method, request.to_url(), headers=request.to_header())
    #
    # resp = conn.getresponse()
    # if resp.status != 200:
    #     print(('Error retrieving access token, the server replied:\n%s' % resp.read()))
    #     return
    # token = oauth.Token.from_string(resp.read())
    # config['telldus']['requesttoken'] = None
    # config['telldus']['requesttokensecret'] = None
    # config['telldus']['token'] = str(token.key)
    # config['telldus']['tokentecret'] = str(token.secret)
    # print('Authentication successful, you can now use tdtool')
    # saveConfig()


def authenticate():
    try:
        opts, args = getopt.getopt(sys.argv[1:], '', ['authenticate'])
        for opt, arg in opts:
            if opt in '--authenticate':
                getAccessToken()
                return
    except getopt.GetoptError:
        pass
    requestToken()


def do_subscribe(client):
    # subscribe to any topic setting a value to a device
    client.subscribe(project + '/+/setValue')
    # enable verbosity
    client.subscribe(project + '/verbose')
    # subscribe to explicit device status request
    client.subscribe(project + '/getDevices')


def main():
    global devices
    
    mqtt.Client.connected_flag = False
    devices = listDevices()
    
    mqtt.Client.devices = []
    # Connect to mqtt bus
    uid = config['mqtt']['uid']
    host = config['mqtt']['host']
    port = config['mqtt']['port']

    uname, pwd = get_vault(uid)
    client = mqtt.Client(project)
    client.username_pw_set(username=uname, password=pwd)
    client.on_connect = on_connect
    client.on_message = on_message
    duration = int(config['mqtt']['duration'])
    print('Duration: ' + str(duration))
    client.loop_start()
    do_mqtt_connect(client, host, port)
    
    while True:
        client.on_message = on_message
        # Get device list ans state
        r = publishDevices(client)
        if not r:
            print('reconnecting')
            do_mqtt_connect(client, host)
            r = publishDevices(client)

        r = publishSensors(client)
        if not r:
            print('reconnecting')
            do_mqtt_connect(client, host)
            r = publishSensors(client)
        print('.', end='')
        sys.stdout.flush()
        if duration == 0:
            sys.exit(0)
        else:
            sleep(duration)


if __name__ == "__main__":
    main()
