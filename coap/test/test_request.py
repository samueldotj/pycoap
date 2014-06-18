"""
Functional tests for CoAP requests.
"""

import time

from ..coap import request, MethodCode, Coap
from ..code_registry import ResponseCode


def test_simple_message():
    result = request('coap://coap.me/hello')
    assert result.payload == 'world' and result.response_code == ResponseCode.content


def test_separate_response():
    result = request('coap://coap.me/separate')
    assert result.payload == 'That took a long time' and result.response_code == ResponseCode.content


def test_block2():
    result = request('coap://coap.me/query')
    assert result.payload == 'You asked me about: Nothing particular.' and result.response_code == ResponseCode.content


def test_block1_post():
    result = request('coap://coap.me/large-create', MethodCode.post, payload='test update ' * 100)
    assert result.payload == '' and result.response_code == ResponseCode.created


def test_block1_put():
    result = request('coap://coap.me/large-update', MethodCode.put, payload='test update ' * 100)
    assert result.payload == '' and result.response_code == ResponseCode.changed


def _obs_basic_callback(payload, msg):
    _obs_basic_callback.counter += 1

def test_obs_basic():
    _obs_basic_callback.counter = 0
    coap = Coap('iot.eclipse.org')
    result = coap.observe('obs', _obs_basic_callback)
    time.sleep(5)
    coap.stop_observe('obs')
    coap.destroy()
    assert _obs_basic_callback.counter >= 2
