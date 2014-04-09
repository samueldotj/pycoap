from ..code_registry import OptionNumber
from ..message import CoapMessage, CoapOption


def test_build_coap_option():
    option = CoapOption(option_number=OptionNumber.uri_path, option_value='test')


def test_build_coap_message():
    msg = CoapMessage()
