# Python EDLink N8

This provides some functionality of the edlink-n8 portion of [krikzz/EDN8-PRO](https://github.com/krikzz/EDN8-PRO) in python.

* Launch rom
* Apply ips/bps patch when launching rom
* Use as module to interact with fifo queue

## No Install

Requires `pyserial` module to be available

    python edlinkn8.py duckhunt.nes

## Install

The install portion is preferably done while in an active virtual environment.  

    git clone https://github.com/zohassadar/python-edlinkn8
    cd python-edlinkn8
    pip install -r requirements.txt
    pip install -e .

### Use

    edlinkn8 mario3.nes -p kaizo.ips
