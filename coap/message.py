"""
Provides abstraction over low level coap protocol data structures(Option and Message).
"""
import struct
import gevent.event
import random
from enum import Enum
from datetime import datetime

from message_format import CoapMessage, CoapOption
from code_registry import MessageType, OptionNumber

COAP_VERSION = 1
COAP_MAX_MESSAGE_ID = 0xFFFF

COAP_ACK_TIMEOUT = 2
COAP_ACK_RANDOM_FACTOR = 1.5
COAP_MAX_RETRANSMIT = 4

COAP_BLOCK_MIN_SIZE = 16
COAP_BLOCK_MAX_SIZE = 1024

#Possible block payload sizes
_COAP_BLOCK_SIZES = [16, 32, 64, 128, 256, 512, 1024]


class MessageState(int, Enum):
    """ State machine states
    """
    init = 0
    to_be_received = 1

    wait_for_send = 2
    wait_for_ack = 3
    wait_for_response = 4
    wait_for_free = 5
    wait_for_updates = 6

    @staticmethod
    def get_str(value):
        result = [
            'init',
            'to_be_received',
            'wait_for_send',
            'wait_for_ack',
            'wait_for_response',
            'wait_for_free',
            'wait_for_updates'
        ]
        return result[value].upper()


class MessageStatus(int, Enum):
    """ Message status
    """
    success = 0
    failed = 1

    ack_timeout = 2
    response_timeout = 3
    reset_received = 4
    observe_timeout = 5

    @staticmethod
    def get_str(value):
        result = [
            'success',
            'failed',
            'ack_timeout'
            'response_timeout',
            'reset_received',
            'observe_timeout'
        ]
        return result[value].upper()

class Option(CoapOption):
    """ Subclass of CoapOptions to provide additional services(for now nothing).
    """
    def __init__(self, option_number, option_value, last_option_number=0):
        CoapOption.__init__(self, option_number=option_number, option_value=option_value, last_option_number=last_option_number)

    @staticmethod
    def block_value_encode(block_number, more, size):
        """
        Encodes given block number, more and size to form a CoAP block option value as byte string.
        """
        if size > COAP_BLOCK_MAX_SIZE:
            raise 'Invalid size {0}'.format(size)

        more_bit = 1 if more else 0
        szx = 0
        for szx, size_value in enumerate(_COAP_BLOCK_SIZES):
            if size <= size_value:
                break

        value = (block_number << 4) | (more_bit << 3) | szx
        bit_len = value.bit_length()
        byte_len = (bit_len / 8) + (1 if bit_len % 8 != 0 else 0)
        if byte_len == 1:
            return struct.pack('B', value)
        elif byte_len == 2:
            return struct.pack('BB', value >> 8, value & 0xff)
        elif byte_len == 3:
            return struct.pack('BBB', value >> 16, value >> 8, value & 0xff)
        else:
            raise 'Invalid Block size {0}'.format(size)

    @staticmethod
    def block_value_decode(value):
        """
        Decodes given CoAP block option value(byte stream) into block number, more and size.
        """
        if len(value) == 0:
            return 0, False, 0
        elif len(value) == 1:
            option_value, = struct.unpack('B', value)
        elif len(value) == 2:
            value1, value2 = struct.unpack('BB', value)
            option_value = (value1 << 8) | value2
        elif len(value) == 3:
            value1, value2, value3 = struct.unpack('BBB', value)
            option_value = (value1 << 16) | (value2 << 8) | value3

        block_number = option_value >> 4
        more = ((option_value >> 3) & 1) != 0
        szx = option_value & 0b111
        size = 2 ** (szx + 4)

        return block_number, more, size


class Message(CoapMessage):
    """ Subclass of CoapMessage to provide additional services(such as timeout, retransmission)"""
    def __init__(self, message_id=0, message_type=MessageType.confirmable, class_code=0, class_detail=0,
                 token='', options=None, payload=None, block1_size=0):

        assert payload is None or block1_size in _COAP_BLOCK_SIZES

        if options is None:
            options = []

        #Original payload which should be send to server(through PUT/POST request)
        self.block1_payload = payload
        #Preferred block size should be used in block1 request
        self.block1_preferred_size = block1_size

        #Payload for this trip
        if payload and len(payload) > block1_size:
            payload = payload[:block1_size]

        CoapMessage.__init__(self, version=COAP_VERSION, message_type=message_type, message_id=message_id,
                             class_code=class_code, class_detail=class_detail,
                             token=token, token_length=len(token), options=options, payload=payload)

        #assert token is None or type(token) is bytearray
        assert self.token_length in [0, 1, 2, 4, 8]

        #State machine states
        self.state = MessageState.init
        #When was the message state changed.
        self._state_change_timestamp = datetime.now()

        #Time out for this message
        #Using this timeout, _state_change_timestamp and datetime.now() it is easy to find whether timeout happened or not.
        self.timeout = random.uniform(COAP_ACK_TIMEOUT, COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR)

        #How many times this message was retransmitted(because of timeout).
        # Once this count reaches COAP_MAX_RETRANSMIT the message will be set to failed state.
        self.retransmission_counter = 0

        #Status of the request/response
        self.status = MessageStatus.success

        #Messages received from the other side as a reply
        self.server_reply_list = []

        #An event on which callers can wait.
        #This event will be triggered once the coap message it transmitted and received a response or timeout.
        self.transaction_complete_event = gevent.event.Event()

        # Observe specific fields
        self.callback = None
        self.age = -1.0

        opt = self.find_option(OptionNumber.uri_path)
        if len(opt) > 0:
            self.url = opt[0].value
        else:
            self.url = ''

    def recycle(self, msg_id):
        """ Recycle the given message so that it can be used to send copy/similar message again.
            Note - Options are not cleared and same token is used.
        """
        self.state = MessageState.init
        self.message_id = msg_id
        self.retransmission_counter = 0

    def change_state(self, new_state):
        """ Change messages state to given new state.

        Also record when this change happened(_state_change_timestamp). This is timestamp is used in timeout calculation.
        """
        if self.state == MessageState.init:
            assert new_state == MessageState.wait_for_send or new_state == MessageState.to_be_received

        self.state = new_state
        self._state_change_timestamp = datetime.now()

    @staticmethod
    def parse(data):
        coap_msg = CoapMessage.parse(data)
        msg = Message()
        #Copy all the CoapMessage attributes to Message object.
        msg.__dict__.update(coap_msg.__dict__)
        return msg

    def add_option(self, option):
        """ Adds given options to the option list."""
        self.coap_option.append(option)

    def find_option(self, option_number):
        """ Returns given option_number in the current message and returns result as a list."""
        return [option for option in self.coap_option if option.option_number == option_number]
        #return filter(lambda option: option.option_number == option_number, self.coap_option)

    def has_observe_option(self):
        """ Returns True if the message has Observe option set"""
        return len(self.find_option(OptionNumber.observe)) > 0

    def remove_option(self, option_number):
        """ Removes the given option(by options number) from the option list.
        Note - If more than one option found for the given option number, all of them are removed.
        """
        for index, option in enumerate(self.coap_option):
            if option.option_number == option_number:
                del self.coap_option[index]

    def get_age_from_option(self):
        """ Finds max age option in the message and returns the value.
        """
        opt = self.find_option(OptionNumber.max_age)
        if len(opt) > 0:
            fmt = 'I'
            if opt[0].length == 1:
                fmt = 'B'
            elif opt[0].length == 2:
                fmt = 'H'
            return struct.unpack(fmt, opt[0].value)[0]
        return -1

    def get_timeout(self):
        """ Returns timeout remaining in seconds.
        +ve value means the timeout is in future.
        -ve value means it is already late.
        """
        passed_time = (datetime.now() - self._state_change_timestamp).total_seconds()
        if self.age == -1:
            return self.timeout - passed_time
        else:
            return self.age - passed_time


class MessageIdGenerator():
    """ An abstract class to generate message IDs.

        See SequenceMessageIdGenerator() for sample implementation.
    """
    def __init__(self, start_number):
        pass

    def get_next_id(self):
        """ Return next unique id within the CoAP time span.
        """
        return None


class TokenGenerator():
    """ An abstract class to generate message tokens.

        See SequenceTokenGenerator() for sample implementation.
    """

    def __init__(self, token_length=4):
        """ token_length - length of the tokens in bytes."""
        pass

    def get_next_id(self):
        """ Return next unique id within the CoAP time span.
        """
        return None


class SequenceMessageIdGenerator(MessageIdGenerator):
    def __init__(self):
        # Starts with the a random number as requried by CoAP spec.
        self._next_message_id = random.randint(1, COAP_MAX_MESSAGE_ID)

    def get_next_id(self):
        """ Returns the next sequence number.
        """
        self._next_message_id += 1
        if self._next_message_id == COAP_MAX_MESSAGE_ID:
            self._next_message_id = 1
        return self._next_message_id


class SequenceTokenGenerator(TokenGenerator):
    def __init__(self, token_length=4):
        assert token_length == 1 or token_length == 2 or token_length == 4 or token_length == 8
        max_number = (1 << (token_length * 8)) - 1
        self._next_token = random.randint(1, max_number)
        self._max_number = max_number
        self._token_length = token_length

    def get_next_token(self):
        """ Generates a new token.
        """
        self._next_token += 1
        if self._next_token == self._max_number:
            self._next_token = 1

        if self._token_length == 1:
            fmt = 'B'
        elif self._token_length == 2:
            fmt = 'H'
        elif self._token_length == 4:
            fmt = 'I'
        elif self._token_length == 8:
            fmt = 'Q'

        return struct.pack('!' + fmt, self._next_token)
