# IOT for SGENABLE dated 16 June 2016
# Python program working on Pi3. contains polling for Beacon signals, pass the Beacon parameters to AWS IOT.
# Using AWS IOT to ascertain status such as Authorised vehicle, Occupied Parking Lot.
# Sensors: include Estimote bluetooth beacon and Ultrasonic sensor
# AWS IOT include a g56pi, g56lot, g56trace
# actuating the SMS, CallPhone, Email, Slack, LED, LCD

# codes lifted off LUPYUAN contribution. Refer to LUPYUAN for Bluetooth BLUEZ installation steps on Pi3.

# Constraints: working on single Pi, scalable to multiple devices.
