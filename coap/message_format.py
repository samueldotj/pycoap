"""
Defines CoAP message as specified in the CoAP spec section 3.
http://tools.ietf.org/html/draft-ietf-core-coap-18#section-3
"""

from construct import Struct, EmbeddedBitStruct, BitField, Switch, Byte, UBInt8, UBInt16, \
    Pass, Field, Optional, If, OptionalGreedyRange, Peek, Embed, Container
from construct_ext import RepeatUntilExclude
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

# option_full defines the construct for a full coap option.
option_full = Struct('option_full',
                     EmbeddedBitStruct(
                         BitField('delta', 4),
                         BitField('length', 4)),
                     Switch('delta_extended', lambda ctx: ctx.delta,
                            {
                                ONE_BYTE_MARKER: UBInt8('value'),
                                TWO_BYTE_MARKER: UBInt16('value')},
                            default=Pass),
                     Switch('length_extended', lambda ctx: ctx.length,
                            {
                                ONE_BYTE_MARKER: UBInt8('value'),
                                TWO_BYTE_MARKER: UBInt16('value')
                            },
                            default=Pass),
                     Field('value', option_length))

# coap_option evaluates to option_full if the next byte in stream is not payload marker.
coap_option = Struct('coap_option',
                     Optional(Peek(UBInt8("is_payload"))),
                     If(lambda ctx: ctx.is_payload != PAYLOAD_MARK, Embed(option_full)))

# Defines payload marker and the following payload
payload = Struct('payload',
                 UBInt8("marker"),
                 OptionalGreedyRange(Byte("value")))

# Defines a full coap message - header + [options] + [payload_marker, payload]
coap_message = Struct('coap_message',
                      EmbeddedBitStruct(BitField('version', 2),
                                        BitField('type', 2),
                                        BitField('token_length', 4),
                                        BitField('class_code', 3),
                                        BitField('class_detail', 5),),
                      UBInt16('message_id'),
                      Field('token', lambda ctx: ctx.token_length),

                      RepeatUntilExclude(lambda obj, ctx: obj is None or obj.is_payload == PAYLOAD_MARK, Optional(coap_option)),

                      Optional(Peek(UBInt8("payload_marker"))),
                      If(lambda ctx: ctx.payload_marker == PAYLOAD_MARK, payload))


class CoapOption():
    """ Container for CoAP option construct."""
    def __init__(self, option_number, option_value, last_option_number=0):
        self.option_number = option_number
        self.value = option_value
        self.delta, self.delta_extended = self._value_to_len_ext(option_number - last_option_number)
        self.length, self.length_extended = self._value_to_len_ext(len(option_value))
        self.is_payload = 0

    def _value_to_len_ext(self, length):
        """ Returns delta and delta_ext for a given length."""
        if length <= 12:
            return length, None
        else:
            if length < TWO_BYTE_START:
                return ONE_BYTE_MARKER, length - ONE_BYTE_START
            else:
                return TWO_BYTE_MARKER, length - TWO_BYTE_START

    @staticmethod
    def _len_ext_to_value(delta, delta_ext):
        """ Returns length for given delta and delta_ext."""
        if delta == ONE_BYTE_MARKER:
            return ONE_BYTE_START + delta_ext
        elif delta == TWO_BYTE_MARKER:
            return TWO_BYTE_START + delta_ext
        else:
            return delta

    def fix_option_number(self, last_option_number):
        """ Fix delta and delta_ext fields in the option based on the last option."""
        self.delta, self.delta_extended = self._value_to_len_ext(self.option_number - last_option_number)

    def build(self):
        """ Returns CoAP option as a bytearray."""
        return option_full.build(self)

    @staticmethod
    def parse(data, last_option_number=0):
        cont = coap_option.parse(data)
        option_number = CoapOption._len_ext_to_value(cont.delta, cont.delta_extended)
        con = CoapOption(option_number=last_option_number + option_number, option_value=cont.value)
        # overwrite the calculated values with read value
        con.__dict__.update(cont)
        return con

    def __str__(self):
        return 'option_no={no} length={length}' .format(no=self.option_number, length=self.length)

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


class CoapMessage():
    """ Container for coap message construct."""
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
        self.coap_option = options
        self.set_payload(payload)

    def set_payload(self, payload):
        if payload and len(payload) > 0:
            self.payload_marker = PAYLOAD_MARK
            self.payload = Container(marker=PAYLOAD_MARK, value=bytearray(payload))
        else:
            self.payload_marker = 0
            self.payload = Container(marker=0, value='')

    def build(self):
        """ Returns CoAP message as a bytearray.
        """
        if self.coap_option:
            self.coap_option.sort(key=lambda o: o.option_number if o else OptionNumber.max)
            last_option_number = 0
            for opt in self.coap_option:
                opt.fix_option_number(last_option_number)
                last_option_number = opt.option_number

        return coap_message.build(self)

    @staticmethod
    def parse(data):
        msg = coap_message.parse(data)
        last_option_number = 0
        options = []
        for opt in msg.coap_option:
            option = CoapOption.parse(coap_option.build(opt), last_option_number=last_option_number)
            options.append(option)
            last_option_number = options[-1].option_number

        payload = msg.payload.value if msg.payload else None

        return CoapMessage(version=msg.version, message_type=msg.type, message_id=msg.message_id,
                           class_code=msg.class_code, class_detail=msg.class_detail,
                           token_length=msg.token_length, token=msg.token, options=options,
                           payload=payload)

    def __str__(self):
        options_str = ''
        for option in self.coap_option:
            options_str += ' \n {0}'.format(str(option))
        return 'id={id} token={token} type={type} code={code}.{detail} payload length={len}{options}'\
            .format(id=self.message_id, token=self.token, type=self.type, code=self.class_code,
                    detail=self.class_detail, len=len(self.payload.value), options=options_str)

