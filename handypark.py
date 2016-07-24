#!/usr/bin/env python3

# Send beacons detected periodically to AWS IoT.  Based on bluez library.
# Must be run with "sudo python3"

import time
import datetime
import ssl
import json
import paho.mqtt.client as mqtt
import bluetooth.ble as ble
import grovepi

# LCD import
import time, sys
import RPi.GPIO as GPIO
import smbus

# LED import
from grovepi import *

# Connect buzzer to D8, LED to D4 and Ultrasonic ranger to D7
buzzer = 8
led = 4
ultrasonic_ranger = 7

grovepi.pinMode(buzzer, "OUTPUT")
grovepi.pinMode(led, "OUTPUT")


# TODO: Change this to the name of our Raspberry Pi, also known as our "Thing Name"
deviceName = "g46pi"
deviceName_actuation = "g46pi_actuation"

# Public certificate of our Raspberry Pi, as provided by AWS IoT.
deviceCertificate = "tp-iot-certificate.pem.crt"
# Private key of our Raspberry Pi, as provided by AWS IoT.
devicePrivateKey = "tp-iot-private.pem.key"
# Root certificate to authenticate AWS IoT when we connect to their server.
awsCert = "aws-iot-rootCA.crt"

isConnected = False


# This is the main logic of the program.  We connect to AWS IoT via MQTT, send sensor data periodically to AWS IoT,
# and handle any actuation commands received from AWS IoT.
def main():
    global isConnected
    # Create an MQTT client for connecting to AWS IoT via MQTT.
    client = mqtt.Client(deviceName + "_sr")  # Client ID must be unique because AWS will disconnect any duplicates.
    client.on_connect = on_connect  # When connected, call on_connect.
    client.on_message = on_message  # When message received, call on_message.
    client.on_log = on_log  # When logging debug messages, call on_log.

    # Set the certificates and private key for connecting to AWS IoT.  TLS 1.2 is mandatory for AWS IoT and is supported
    # only in Python 3.4 and later, compiled with OpenSSL 1.0.1 and later.
    client.tls_set(awsCert, deviceCertificate, devicePrivateKey, ssl.CERT_REQUIRED, ssl.PROTOCOL_TLSv1_2)

    # Connect to AWS IoT server.  Use AWS command line "aws iot describe-endpoint" to get the address.
    print("Connecting to AWS IoT...")
    client.connect("A1P01IYM2DOZA0.iot.us-west-2.amazonaws.com", 8883, 60)

    # Start a background thread to process the MQTT network commands concurrently, including auto-reconnection.
    client.loop_start()

    # Create the beacon service for scanning beacons.
    beacon_service = ble.BeaconService()

    # Loop forever.
    while True:
        try:
            # If we are not connected yet to AWS IoT, wait 1 second and try again.
            if not isConnected:
                time.sleep(1)
                continue

            # Scan for beacons and add to the sensor data payload.
            beacons = {}
            # Nick: Added to initialise beacon_id value
            beacon_id = ""
            beacons_detected = beacon_service.scan(2)
            for beacon_address, beacon_info in list(beacons_detected.items()):
                # For each beacon found, add to the payload. Need to flip the bytes.
                beacon = {
                    "uuid": beacon_info[0].replace('-', ''),
                    "major": (beacon_info[1] % 256) * 256 + beacon_info[1] // 256,
                    "minor": (beacon_info[2] % 256) * 256 + beacon_info[2] // 256,
                    "power": beacon_info[3],
                    "rssi": beacon_info[4],
                    "address": beacon_address
                }
                # Beacon ID is B_(uuid)_(major)_(minor). This format allows us
                # to match beacon IDs within IoT rules. Prepad major and minor
                # with 0s to max length, so that we can slice beacons by fixed
                # length in IoT rules. Sample beacon ID:
                # "B_b9407f30f5f8466eaff925556b57fe6d_00602_29434"
                beacon_id = "B_" + beacon["uuid"] + "_" + \
                            str(beacon["major"]).rjust(5, '0') + "_" + \
                            str(beacon["minor"]).rjust(5, '0')
                # Nick: Originally beacon["id"] = beacons
                beacon["id"] = beacon_id
                beacons[beacon_id] = beacon

            # Prepare our sensor data in JSON format.
            # Nick: For beacon, only send beacon_id since it is uniquely identifiable incl. UUID+major+minor
            payload = {
                "state": {
                    "reported": {
                        "cplot": "lot1",
                        "beacons": beacon_id,
                        "distance": grovepi.ultrasonicRead(ultrasonic_ranger),
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                }
            }


            print("Sending sensor data to AWS IoT...\n" +
                  json.dumps(payload, indent=4, separators=(',', ': ')))

            # Publish our sensor data to AWS IoT via the MQTT topic, also known as updating our "Thing Shadow".
            client.publish("$aws/things/" + deviceName + "/shadow/update", json.dumps(payload))
            print("Sent to AWS IoT")

            # Wait 30 seconds before sending the next set of sensor data.
            time.sleep(30)

        except KeyboardInterrupt:
            # Stop the program when we press Ctrl-C.
            break
        except Exception as e:
            # For all other errors, we wait a while and resume.
            print("Exception: " + str(e))
            time.sleep(10)
            continue


# This is called when we are connected to AWS IoT via MQTT.
# We subscribe for notifications of desired state updates.
def on_connect(client, userdata, flags, rc):
    global isConnected
    isConnected = True
    print("Connected to AWS IoT")
    # Nick: Subscribe to MQTT topic: deviceName_actuation so that we will receive notifications of desired states.
    topic = "$aws/things/" + deviceName_actuation + "/shadow/update/accepted"
    print("Subscribing to MQTT topic " + topic)
    client.subscribe(topic)
    # Subscribe to our MQTT topic so that we will receive notifications of updates.
    topic = "$aws/things/" + deviceName + "/shadow/update/accepted"
    print("Subscribing to MQTT topic " + topic)
    client.subscribe(topic)


# This is called when we receive a subscription notification from AWS IoT.
def on_message(client, userdata, msg):
    # Convert the JSON payload to a Python dictionary.
    # The payload is in binary format so we need to decode as UTF-8.
    payload2 = json.loads(msg.payload.decode("utf-8"))
    print("Received message, topic: " + msg.topic + ", payload:\n" +
          json.dumps(payload2, indent=4, separators=(',', ': ')))

    # If there is a desired state in this message, then we actuate, e.g. if we see "led=on", we switch on the LED.
    if payload2.get("state") is not None and payload2["state"].get("desired") is not None:
        # Get the desired state and loop through all attributes inside.
        desired_state = payload2["state"]["desired"]
        for attribute in desired_state:
            # We handle the attribute and desired value by actuating.
            value = desired_state.get(attribute)
            actuate(client, attribute, value)


# Send the reported state of our actuator to AWS IoT after it has been triggered, e.g. "led": "on".
def send_reported_state(client, attribute, value):
    # Prepare our sensor data in JSON format.
    payload = {
        "state": {
            "reported": {
                attribute: value,
                "timestamp": datetime.datetime.now().isoformat()
            }
        }
    }
    print("Sending sensor data to AWS IoT...\n" +
          json.dumps(payload, indent=4, separators=(',', ': ')))

    # Publish our sensor data to AWS IoT via the MQTT topic, also known as updating our "Thing Shadow".
    client.publish("$aws/things/" + deviceName_actuation + "/shadow/update", json.dumps(payload))
    print("Sent to AWS IoT")

    # Print out log messages for tracing.
    def on_log(client, userdata, level, buf):
        print("Log: " + buf)


# Control my actuators based on the specified attribute and value,
# e.g. "led=on" will switch on my LED.

def actuate(client, attribute, value):
    if attribute == "timestamp":
        # Ignore the timestamp attribute, it's only for info.
        return
        print("Setting " + attribute + " to " + value + "...")

    if attribute == "led":
        # We actuate the LED for "on", "off" or "flash1".
        if value == "on":
            # Switch on LED.
            grovepi.digitalWrite(led, 1)
            send_reported_state(client, "led", "on")
            return
        elif value == "off":
            # Switch off LED.
            grovepi.digitalWrite(led, 0)
            send_reported_state(client, "led", "off")
            return
        elif value == "flash1":
            #Switch on LED, wait 1 second, switch it off.
            grovepi.digitalWrite(led, 1)
            send_reported_state(client, "led", "on")
            time.sleep(1)
            grovepi.digitalWrite(led, 0)
            send_reported_state(client, "led", "off")
            time.sleep(1)
            return
    # Show an error if attribute or value are incorrect.
        else:
            print("Error: Don't know how to set " + attribute + " to " + value)

    # here is the start of the buzzer part---------------------
    # Connect the Grove Buzzer to digital port D8
    # SIG,NC,VCC,GND


    if attribute == "buzzer":
        if value == "on":
            # Start buzzing for 8 second; in actual implementation, it can be made to buzz until violation is over
            grovepi.digitalWrite(buzzer, 8)
            print('start buzzer')
            time.sleep(1)

            # Stop buzzing after 1 second, since it is for demo
            grovepi.digitalWrite(buzzer, 0)
            print('stop')
            send_reported_state(client, "buzzer", "on")
            return
            
        elif value == "off":
            # Switch off buzzer. In this demo, this condition has no effect since buzzer only buzz for 1 sec. This is included for completeness sake in case future(actual) implementation need to buzz until violation is over.
            grovepi.digitalWrite(buzzer, 0)
            send_reported_state(client, "buzzer", "off")
            return
            # except KeyboardInterrupt:
            #	grovepi.digitalWrite(buzzer,0)
            #	break
            # except IOError:
            #	print ("Error")        
        else:
            print("no buzzer actuated")


    # here is the end of the buzzer part------------------------

    # here is the start of the LCD part ------------------------
    if attribute == "lcd":
        # We actuate the lcd
        if value == "on":

            # this device has two I2C addresses
            DISPLAY_RGB_ADDR = 0x62
            DISPLAY_TEXT_ADDR = 0x3e

            # use the bus that matches your raspi version
            rev = GPIO.RPI_REVISION
            if rev == 2 or rev == 3:
                bus = smbus.SMBus(1)
            else:
                bus = smbus.SMBus(0)

            # set backlight to (R,G,B) (values from 0..255 for each)
            def setRGB(r,g,b):
                bus.write_byte_data(DISPLAY_RGB_ADDR,0,0)
                bus.write_byte_data(DISPLAY_RGB_ADDR,1,0)
                bus.write_byte_data(DISPLAY_RGB_ADDR,0x08,0xaa)
                bus.write_byte_data(DISPLAY_RGB_ADDR,4,r)
                bus.write_byte_data(DISPLAY_RGB_ADDR,3,g)
                bus.write_byte_data(DISPLAY_RGB_ADDR,2,b)

            # send command to display (no need for external use)    
            def textCommand(cmd):
                bus.write_byte_data(DISPLAY_TEXT_ADDR,0x80,cmd)

            # set display text \n for second line(or auto wrap)     
            def setText(text):
                textCommand(0x01) # clear display
                time.sleep(.05)
                textCommand(0x08 | 0x04) # display on, no cursor
                textCommand(0x28) # 2 lines
                time.sleep(.05)
                count = 0
                row = 0
                for c in text:
                    if c == '\n' or count == 16:
                        count = 0
                        row += 1
                        if row == 2:
                            break
                        textCommand(0xc0)
                        if c == '\n':
                            continue
                    count += 1
                    bus.write_byte_data(DISPLAY_TEXT_ADDR,0x40,ord(c))


            # LCD warning
            if __name__=="__main__":
                setText("Illegal Parking!\nWheelclamp OTW!")
                setRGB(0,255,0)
                send_reported_state(client, "lcd", "on")
                return


        elif value == "off":

            # this device has two I2C addresses
            DISPLAY_RGB_ADDR = 0x62
            DISPLAY_TEXT_ADDR = 0x3e

            # use the bus that matches your raspi version
            rev = GPIO.RPI_REVISION
            if rev == 2 or rev == 3:
                bus = smbus.SMBus(1)
            else:
                bus = smbus.SMBus(0)

            # set backlight to (R,G,B) (values from 0..255 for each)
            def setRGB(r,g,b):
                bus.write_byte_data(DISPLAY_RGB_ADDR,0,0)
                bus.write_byte_data(DISPLAY_RGB_ADDR,1,0)
                bus.write_byte_data(DISPLAY_RGB_ADDR,0x08,0xaa)
                bus.write_byte_data(DISPLAY_RGB_ADDR,4,r)
                bus.write_byte_data(DISPLAY_RGB_ADDR,3,g)
                bus.write_byte_data(DISPLAY_RGB_ADDR,2,b)

            # send command to display (no need for external use)    
            def textCommand(cmd):
                bus.write_byte_data(DISPLAY_TEXT_ADDR,0x80,cmd)

            # Switch off LCD
            if __name__=="__main__":
                textCommand(0x01)
                setRGB(0,0,0)
                send_reported_state(client, "lcd", "off")
                return


# here is the end of the LCD part----------------------


# Print out log messages for tracing.
def on_log(client, userdata, level, buf):
    print("Log: " + buf)


# Start the main program.
main()
