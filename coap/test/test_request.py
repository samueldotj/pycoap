from ..code_registry import MethodCode, MessageType
from ..coap import Coap
import binascii

def test_build_message():
    c = Coap('coap.me')
    result1 = c.get('hello')
    assert str(bytearray(result1.server_reply_list[0].payload)) == '\xffworld'

    result2 = c.get('separate')
    assert str(bytearray(result2.server_reply_list[0].payload)) == '\xffThat took a long time'

    c.destroy()

