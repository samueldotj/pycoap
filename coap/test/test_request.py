"""
Functional tests for CoAP requests.
"""

from ..coap import request, MethodCode
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
