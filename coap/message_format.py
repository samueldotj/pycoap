"""
Defines CoAP message as specified in the CoAP spec section 3.
http://tools.ietf.org/html/draft-ietf-core-coap-18#section-3
"""

from construct import *
from code_registry import OptionNumber

ONE_BYTE_MARKER = 13
TWO_BYTE_MARKER = 14

ONE_BYTE_START = 13
TWO_BYTE_START = 269

PAYLOAD_MARK = 0xff


def option_length(ctx):
    """ Returns CoAP options length by decoding the length and length extended fields.
    """
    if ctx.length <= 12:
        return ctx.length

    assert ctx.length == ONE_BYTE_MARKER or ctx.length == TWO_BYTE_MARKER
    return ctx.length_extended + (ONE_BYTE_START if ctx.length == ONE_BYTE_MARKER else TWO_BYTE_START)

option_header = Struct('coap_option',
                     EmbeddedBitStruct(
                         BitField('delta', 4),
                         BitField('length', 4)),
                         Switch('delta_extended', lambda ctx: ctx.delta,
                                {
                                    ONE_BYTE_MARKER: UBInt8('value'),
                                    TWO_BYTE_MARKER: UBInt16('value')
                                },
                                default=Pass),
                         Switch('length_extended', lambda ctx: ctx.length,
                                {
                                    ONE_BYTE_MARKER: UBInt8('value'),
                                    TWO_BYTE_MARKER: UBInt16('value')
                                },
                                default=Pass),
                         Field('value', option_length))

coap_option = Struct('coap_option',
                     Peek(UBInt8("is_payload")),
                     If(lambda ctx: ctx.is_payload != PAYLOAD_MARK, Embed(option_header))
                     )

coap_message = Struct('coap_message',
                      EmbeddedBitStruct(BitField('version', 2),
                                        BitField('type', 2),
                                        BitField('token_length', 4),
                                        BitField('class_code', 3),
                                        BitField('class_detail', 5),
                                        ),
                      UBInt16('message_id'),
                      Field('token', lambda ctx: ctx.token_length),

                      RepeatUntil(lambda obj, ctx: obj is None or obj.is_payload == PAYLOAD_MARK, Optional(coap_option)),

                      Optional(Peek(UBInt8("payload_marker"), PAYLOAD_MARK)),
                      If(lambda ctx: ctx.payload_marker == PAYLOAD_MARK,
                      OptionalGreedyRange(Byte("payload")))
                      )


class CoapOption:
    """ Container for CoAP option construct.
    """
    def __init__(self, option_number, option_value, last_option_number=0):
        def value_to_len_ext(length):
            if length <= 12:
                return length, None
            else:
                if length < TWO_BYTE_START:
                    return ONE_BYTE_MARKER, length - ONE_BYTE_START
                else:
                    return TWO_BYTE_MARKER, length - TWO_BYTE_START

        self.option_number = option_number
        self.value = option_value
        self.delta, self.delta_extended = value_to_len_ext(option_number - last_option_number)
        self.length, self.length_extended = value_to_len_ext(len(option_value))
        self.is_payload = 0

    def build(self):
        """ Returns CoAP option as a bytearray.
        """
        return coap_option.build(self)

    @staticmethod
    def parse(data, last_option_number=0):
        cont = coap_option.parse(data)
        con = CoapOption(option_number=last_option_number + cont.delta, option_value=cont.value)
        # overwrite the calculated values with read value
        con.__dict__.update(cont)
        return con

    def __str__(self):
        return 'delta = {delta} value={value} length={length} delta_ext={delta_ext} length_ext={length_ext}'\
            .format(delta=self.option_number, value=self.value, length=self.length,
                    delta_ext=self.delta_extended, length_ext=self.length_extended)

    def __eq__(self, other):
        if isinstance(other, CoapOption):
            return self.delta == other.delta and self.delta_extended == other.delta_extended and \
                   self.length == other.length and self.length_extended == other.length_extended and \
                   self.value == other.value
        elif type(other) is Container:
            new_option = CoapOption(option_number=0, option_value='')
            # overwrite the calculated values with read value
            new_option.__dict__.update(other)
            return self == new_option
        else:
            raise Exception('Can not compare {0} with {1}'.format(type(self), type(other)))


class CoapMessage:
    """ Container for coap message construct.
    """
    def __init__(self, version=0, message_type=0, class_code=0, class_detail=0, message_id=0,
                 token_length=0, token='', options=None, payload=''):
        if options is None:
            options = []
        self.version = version
        self.type = message_type
        self.class_code = class_code
        self.class_detail = class_detail
        self.message_id = message_id
        self.token_length = token_length
        self.token = token
        self.coap_option = options + [None]
        self.payload = payload if payload is not None else ''
        if len(self.payload) > 0:
            self.payload_marker = PAYLOAD_MARK
        else:
            self.payload_marker = 0

    def build(self):
        """ Returns CoAP message as a bytearray.
        """
        if self.coap_option:
            self.coap_option.sort(key=lambda o: o.option_number if o else OptionNumber.max)
        return coap_message.build(self)

    @staticmethod
    def parse(data):
        msg = coap_message.parse(data)
        return CoapMessage(version=msg.version, message_type=msg.type, message_id=msg.message_id,
                           class_code=msg.class_code, class_detail=msg.class_detail,
                           token_length=msg.token_length, token=msg.token, options=msg.coap_option,
                           payload=msg.payload)

    def __str__(self):
        return 'id={id} token={token} type={type} code={code}.{detail}'.format(id=self.message_id, token=self.token,
                                                                               type=self.type, code=self.class_code,
                                                                               detail=self.class_detail)

