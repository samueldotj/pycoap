from ..coap import request


def test_simple_message():
    result = request('coap://coap.me/hello')
    assert result.payload == 'world'


def test_separate_response():
    result = request('coap://coap.me/separate')
    assert result.payload == 'That took a long time'


def test_block2():
    result = request('coap://coap.me/query')
    assert result.payload == 'You asked me about: Nothing particular.'
