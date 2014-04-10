"""
Provides abstraction over low level coap protocol data structures(Option and Message).
"""
import struct
import threading
import random
from enum import Enum
from datetime import datetime

from message_format import CoapMessage, CoapOption
from code_registry import MessageType

COAP_VERSION = 1
COAP_MAX_MESSAGE_ID = 0xFFFF

COAP_ACK_TIMEOUT = 2
COAP_ACK_RANDOM_FACTOR = 1.5
COAP_MAX_RETRANSMIT = 4


class MessageState(int, Enum):
    """ State machine states
    """
    init = 0
    to_be_received = 1

    wait_for_send = 2
    wait_for_ack = 3
    wait_for_response = 4
    wait_for_free = 5


class MessageStatus(int, Enum):
    """ Message status
    """
    success = 0
    failed = 1

    ack_timeout = 2
    response_timeout = 3
    reset_received = 4


class Option(CoapOption):
    """ Subclass of CoapOptions to provide additional services(for now nothing).
    """
    def __init__(self, option_number, option_value, last_option_number=0):
        CoapOption.__init__(self, option_number=option_number, option_value=option_value, last_option_number=last_option_number)


class Message(CoapMessage):
    """ Subclass of CoapMessage to provide additional services(such as timeout, retransmission)
    """
    def __init__(self, message_id=0, message_type=MessageType.confirmable, class_code=0, class_detail=0,
                 token='', options=[], payload=None):
        CoapMessage.__init__(self, version=COAP_VERSION, message_type=message_type, message_id=message_id,
                             class_code=class_code, class_detail=class_detail,
                             token=token, token_length=len(token), options=options, payload=payload if payload else '')

        #assert token is None or type(token) is bytearray
        assert self.token_length in [0, 1, 2, 4, 8]

        """State machine states"""
        self.state = MessageState.init
        """When was the message state changed."""
        self._state_change_timestamp = datetime.now()
        """What is the time out for this message

        Using this timeout, _state_change_timestamp and datetime.now() it is easy to find whether timeout happened or not.
        """
        self.timeout = random.uniform(COAP_ACK_TIMEOUT, COAP_ACK_TIMEOUT * COAP_ACK_RANDOM_FACTOR)
        """How many times this message was retransmitted(because of timeout).

        Once this count reaches COAP_MAX_RETRANSMIT the message will be set to failed state.
        """
        self.retransmission_counter = 0

        """Status of the request/response"""
        self.status = MessageStatus.success
        """"Messages received from the other side as a reply"""
        self.server_reply_list = []

        """An event on which callers can wait.

        This event will be triggered once the coap message it transmitted and received a response or timeout.
        """
        self.transaction_complete_event = threading.Event()


    def change_state(self, new_state):
        """ Change messages state to given new state.

        Also record when this change happened(_state_change_timestamp). This is timestamp is used in timeout calculation.
        """
        if self.state == MessageState.init:
            assert new_state == MessageState.wait_for_send or new_state == MessageState.to_be_received

        self.state = new_state
        self._state_change_timestamp = datetime.now()

    def get_timeout(self):
        """
        Returns timeout remaining in seconds.
        +ve value means the timeout is in future.
        -ve value means it is already late.
        """
        passed_time = (datetime.now() - self._state_change_timestamp).total_seconds()
        return self.timeout - passed_time

    @staticmethod
    def parse(data):
        coap_msg = CoapMessage.parse(data)
        msg = Message()
        #Copy all the CoapMessage attributes to Message object.
        msg.__dict__.update(coap_msg.__dict__)
        return msg


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
