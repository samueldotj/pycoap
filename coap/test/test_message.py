import binascii
from ..code_registry import OptionNumber, MessageType, MethodCode
from ..message import CoapMessage, CoapOption


def verify_coap_option(bin_data, option_number, option_value):
    """ Helper function to verify CoapOption works for the given arguments.
    """

    #Build an option with given arguments and verify it
    option = CoapOption(option_number=option_number, option_value=option_value)
    assert option.build() == bin_data

    #Parse the given binary data and verify it matches
    option = CoapOption.parse(bin_data)
    assert option.value == option_value
    assert option.length != 15
    length = option.length
    if option.length == 13:
        length = 13 + option.length_extended
    elif option.length == 14:
        length = 269 + option.length_extended
    assert length == len(option_value)

    calc_opt_number = option.delta
    if option.delta == 13:
        calc_opt_number = 13 + option.delta_extended
    elif option.delta == 14:
        calc_opt_number = 269 + option.delta_extended
    assert calc_opt_number == option_number


def test_coap_option():
    # Basic test case to verify CoAP option for URI path works.
    verify_coap_option('\xb4test', OptionNumber.uri_path, 'test')
    verify_coap_option('\xcbtext/plain;', OptionNumber.content_format, 'text/plain;')

    # This test will build an option with very long value and verifies length_extended field is used.
    verify_coap_option('\xbd\x0fthis_is_a_very_long_uri_path', OptionNumber.uri_path, 'this_is_a_very_long_uri_path')

    # This test will build an option with option number > 12 to test delta_extended field.
    verify_coap_option('\xda\x07correct_me', OptionNumber.location_query, 'correct_me')

    # This test will build an option with option number > 12 to test delta_extended field.
    verify_coap_option('\xdd\x07\x02very_long_value', OptionNumber.location_query, 'very_long_value')


def verify_coap_message(bin_data,  message_type, message_id, class_code, class_detail, token, options, payload):
    """ Helper function to verify CoapMessage works for the given arguments.
    """
    if token is None:
        token = ''
    token_length = len(token)
    if payload is None:
        payload = ''
    #Build an option with given arguments and verify it
    msg = CoapMessage(version=1, message_type=message_type, message_id=message_id, class_code=class_code,
                      class_detail=class_detail, token=token, token_length=token_length, options=options, payload=payload)
    assert msg.build() == bin_data

    #Parse the given binary data and verify it matches
    msg = CoapMessage.parse(bin_data)
    assert msg.version == 1
    assert msg.type == message_type
    assert msg.message_id == message_id
    assert msg.class_code == class_code
    assert msg.class_detail == class_detail
    assert msg.token_length == token_length
    if len(options) > 0:
        msg_options = msg.coap_option
        assert len(msg_options) == len(options)
        for idx, opt in enumerate(options):
            print str(opt)
            assert msg_options[idx] == opt
    assert msg.payload == payload


def test_build_coap_message():
    #acknowledgment with empty message.
    verify_coap_message('`\x01\xab\xcd',
                        message_type=MessageType.acknowledgment, message_id=0xabcd, class_code=0, class_detail=MethodCode.get,
                        token='', payload=None, options=[])

    #simple GET request
    verify_coap_message('@\x01\x01\x00\xb5hello',
                        message_type=MessageType.confirmable, message_id=0x100, class_code=0, class_detail=MethodCode.get,
                        token='', payload=None,
                        options=[CoapOption(option_number=OptionNumber.uri_path, option_value='hello')])

    #simple GET request with token
    verify_coap_message('H\x01\x01\x001234abcd\xbd\x01check_my_token',
                        message_type=MessageType.confirmable, message_id=0x100, class_code=0, class_detail=MethodCode.get,
                        token='1234abcd', payload=None,
                        options=[CoapOption(option_number=OptionNumber.uri_path, option_value='check_my_token')])

