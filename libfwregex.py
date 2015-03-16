#!/usr/bin/env python
#
# Library for parsing of Firewall log messages using regex
#
import os
import re
import sys
import time
import datetime

# Debug flag
DEBUG = False

# Different timestamp formats used
reTime = []
reTime.append(dict(regex=r'[a-zA-Z]+\s+[0-9]+ (?P<time>[0-9:]+) (?P<month>[a-zA-Z]+) (?P<day>[0-9]+) (?P<year>[0-9]+)', fields=dict(time=0, year=3, month=1, day=2)))
reTime.append(dict(regex=r'(?P<month>[a-zA-Z]+)\s+(?P<day>[0-9]+) (?P<time>[0-9:]+)', fields=dict(year=None, month=0, day=1, time=2)))

# Regular expressions for info in built connection message
reConn = []

# Cisco ASA/FWSM format (only message code 6-302013 and 6-302015 match)
reConn.append(dict(regex=r'Built (?P<direction>outbound|inbound) (?P<protocol>[a-zA-Z]+) .* for (?P<interface_in>[a-zA-Z0-9_-]+):(?P<src>[0-9.]+)/(?P<sport>[0-9]+) .* to (?P<interface_out>[a-zA-Z0-9_-]+):(?P<dst>[0-9.]+)/(?P<dport>[0-9]+)', \
    fields=dict(direction=0, protocol=1, interface_in=2, src=3, sport=4, interface_out=5, dst=6, dport=7)))

# Fortinet FortiGate CSV format
reConn.append(dict(regex=r'date=(?P<date>[0-9-]+).*type=traffic,subtype=forward,.*,srcip=(?P<src>[0-9.]+),srcport=(?P<sport>[0-9]+),srcintf="(?P<interface_in>[a-zA-Z0-9_-]+)",dstip=(?P<dst>[0-9.]+),dstport=(?P<dport>[0-9]+),dstintf="(?P<interface_out>[a-zA-Z0-9_-]+)",.*,proto=(?P<protocol>[0-9]+)', \
    fields=dict(direction=None, src=0, sport=1, interface_in=2, dst=3, dport=4, interface_out=5, protocol=6)))

# Compile each regex
for ret in reTime:
    ret['RX'] = re.compile(ret['regex'])
for rec in reConn:
    rec['RX'] = re.compile(rec['regex'])


def get_timestamp(line):
    # Only process timestamp
    for ret in reTime:
        matchtime = re.search(ret['regex'], line)
        if matchtime:
            # Return dictionary of time-related data
            return matchtime.groupdict()
    else:
        if DEBUG:
            print('ERROR: Unable to decode time format of line: {0}'.format(line))

        # Unable to decode timestamp
        return None


def get_builtconn(line):
    # Initialize return dict
    data = {}

    # Try each regex until a match is found
    for rec in reConn:
        # Extract info from message
        match = re.search(rec['RX'], line)
        if not match:
            # Try next connection regex
            continue
        else:
            # Match found, first process timestamp
            timedata = get_timestamp(line)
            if timedata:
                # Save time-related data
                data.update(timedata)
            else:
                # Unable to decode timestamp
                return None

            # Save connection-related data
            data.update(match.groupdict())

            # Match found, so return results
            return data
    else:
        if DEBUG:
            print('Regex FAILED for line: {0}'.format(line))

        # No match
        return None

