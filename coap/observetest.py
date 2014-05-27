__author__ = 'mini'

import logging
import coap
from coap import *
from message_format import CoapMessage, CoapOption
import time


cc = observe('coap://iot.eclipse.org/obs',None , True)
time.sleep(20)
#stop observe
cc = observe('coap://iot.eclipse.org/obs',cc,False)
time.sleep(10)
cc.destroy()
