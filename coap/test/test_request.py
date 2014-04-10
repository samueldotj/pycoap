from ..code_registry import MethodCode, MessageType
from ..coap import Coap

def test_build_message():
    c = Coap('coap.me')
    result = c.get('hello')
    print str(bytearray(result.server_reply_list[0].payload))
    c.destroy()

