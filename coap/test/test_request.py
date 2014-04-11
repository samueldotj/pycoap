from ..code_registry import MethodCode, MessageType
from ..coap import Coap
import binascii

def test_build_message():
    c = Coap('coap.me')
    result = c.get('hello')
    assert result.payload == '\xffworld'

    result = c.get('separate')
    assert result.payload == '\xffThat took a long time'

    c.destroy()

