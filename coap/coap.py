"""
This file implements passing Coap Requests and Responses between server and client.

There is a simple state machine which maintains the message states such as ACK, RST. This state machine runs as
a separate thread(_fsm_loop).

asyncore is used for UDP socket options. asyncore runs as a separate thread(_asyncore_loop) to handle
sock receive and send operations. Currently asyncore is mainly used for asynchronous sock.recv().
"""
import threading
import socket
import logging
import asyncore
from datetime import datetime

from code_registry import MethodCode, MessageType, OptionNumber
import message
from message import Message, Option, MessageState, MessageStatus

COAP_DEFAULT_PORT = 5683

UDP_RECEIVE_BUFFER_SIZE = 2048
DEFAULT_REQUEST_TIMEOUT = 5


class Coap(asyncore.dispatcher):
    """ Manages CoAP request to a server.
    """
    def __init__(self, host, port=COAP_DEFAULT_PORT, timeout=DEFAULT_REQUEST_TIMEOUT,
                 message_id_generator=message.SequenceMessageIdGenerator(),
                 token_generator=message.SequenceTokenGenerator()):
        asyncore.dispatcher.__init__(self)

        # decode the given host name and create a socket out of it.
        af, socktype, proto, canonname, sa = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_DGRAM)[0]
        self.create_socket(af, socktype)
        self.connect(sa)

        self.timeout = timeout

        self._id_generator = message_id_generator
        self._token_generator = token_generator

        # CoAP messages are maintained in different lists based on the message state.
        self.message_queues = {
            MessageState.init: [],
            MessageState.to_be_received : [],
            MessageState.wait_for_send: [],
            MessageState.wait_for_ack: [],
            MessageState.wait_for_response: [],
            MessageState.wait_for_free: [],
        }
        # A event to continue state machine processing.
        self.fsm_event = threading.Event()

        # If this flag is set then the threads created by this class should exit.
        self._stop_requested = False

        self.asyncore_thread = threading.Thread(target=self._asyncore_loop)
        self.asyncore_thread.start()

        self.fsm_thread = threading.Thread(target=self._fsm_loop)
        self.fsm_thread.start()

    def __del__(self):
        """ Stops the threads started by this class. """
        asyncore.ExitNow('Stop requested')
        self._stop_requested = True
        self.fsm_event.set()
        self.fsm_thread.join()

    def _asyncore_loop(self):
        asyncore.loop()

    def _get_next_timeout(self):
        """
        Returns the when the next timeout event should fire(in seconds).
        Since the message_queue is arranged in the same order as the messages are arrived, the last entry in the message
        should have less timeout value. So this function will take the least of timeout from last element in the list.
        """
        result = 0
        for state in [MessageState.wait_for_ack, MessageState.wait_for_response, MessageState.wait_for_send]:
            if len(self.message_queues[state]) > 0:
                msg = self.message_queues[state][-1]
                timeout = msg.get_timeout()
                if timeout < result:
                    result = timeout
        return result

    def _fsm_loop(self):
        """
        The main state machine loop.
        The loop would block if there nothing to be done.
        """
        while True:
            # Sleep until something need to be done(either new messages needs to be send or timeout)
            timeout = self._get_next_timeout()
            logging.debug('FSM - Waiting for event with timeout {0}'.format(timeout))
            if timeout > 0:
                self.fsm_event.wait(timeout)
            else:
                self.fsm_event.wait()
            self.fsm_event.clear()

            # Receive messages
            messages = self.message_queues[MessageState.to_be_received]
            logging.debug('FSM - Receive messages {0}'.format(len(messages)))
            for msg in messages:
                self._receive_message(msg)

            # Send all messages in the send queue
            messages = self.message_queues[MessageState.wait_for_send]
            logging.debug('FSM - Send messages {0}'.format(len(messages)))
            for msg in messages:
                self._send_message(msg)

            # Handle timeouts
            for state in [MessageState.wait_for_ack, MessageState.wait_for_response, MessageState.wait_for_send]:
                for msg in reversed(self.message_queues[state]):
                    # check how long we have before the timeout.
                    timeout = msg.get_timeout()
                    if timeout > 0:
                        # since the list ordered by the message arrival there is no need to check further
                        break
                    self._timeout_message(msg)

            if self._stop_requested:
                logging.debug('FSM - Terminating because stop requested')
                return

    def _find_message(self, token, message_id, state):
        """Returns the message with given token and message_id.

        Searches for a matching message in the given message list(based on state).
        If found it returns the list index and message itself.
        If no match found then None is returned.
        """
        for idx, msg in enumerate(self.message_queues[state]):
            if ((token is None and msg.token is None) or token == msg.token) and message_id == msg.message_id:
                return idx, msg
        return None, None

    def _remove_message(self, msg):
        """Removes the given message from the state machine.

        Searches given message in the state machine lists.
        If found removes the message from the state machine and returns True.
        If no match found then returns False.
        """
        idx, unused = self._find_message(msg.token, msg.message_id, msg.state)
        if idx is not None:
            del self.message_queues[msg.state][idx]
            return True

        return False

    def _transition_message(self, msg, new_state):
        """Transitions a message to a new state.

        Changes the message state and also moves the message new state list.
        If the message is not found in the state machine then it would throw an exception.
        """
        if msg.state == MessageState.init or self._remove_message(msg):
            if msg.state == MessageState.init:
                assert new_state == MessageState.wait_for_send or new_state == MessageState.to_be_received
            msg.state_change_timestamp = datetime.now()
            msg.state = new_state
            self.message_queues[new_state].append(msg)
        else:
            raise Exception('Invalid message({0}) state {1} new_state {2}'.format(msg.message_id, msg.state, new_state))

    def _receive_message(self, msg):
        """Handles a received COAP message.

           The state machine calls this function to process a received a CoAP message.
        """
        logging.info('Received CoAP message {0}'.format(str(msg)))
        is_response = msg.class_code in [2, 3, 4, 5]
        if is_response:
            self._remove_message(msg)

            idx, req_msg = self._find_message(msg.token, msg.message_id, MessageState.wait_for_ack)
            if req_msg is None:
                idx, req_msg = self._find_message(msg.token, msg.message_id, MessageState.wait_for_response)
            if req_msg is None:
                logging.warning('Response without request - Ignoring {0}'.format(str(msg)))
                return

            req_msg.server_reply_list.append(msg)
            self._remove_message(req_msg)

            #TODO - find whether what all we got - just ack or both ack and response or reset?

            # wake up threads waiting for this message
            req_msg.transaction_complete_event.set()
        else:
            logging.error('Request is not implemented')

    def _send_message(self, msg):
        """Process a message which needs to be send out.

           Converts the given message in to bytestream and then sends it over the asyncore socket.
           Then places the message in appropriate wait queue to wait for repsonse.
        """
        logging.info('Sending CoAP message {0}'.format(str(msg)))

        #TODO - implement response sending.
        assert msg.class_code == 0

        self.send(msg.build())
        if msg.type == MessageType.confirmable:
            self._transition_message(msg, MessageState.wait_for_ack)
        else:
            self._transition_message(msg, MessageState.wait_for_response)

    def _timeout_message(self, msg):
        """Timeout given message by requeueing it.
        """
        assert msg.get_timeout() <= 0
        if msg.retransmission_counter < message.COAP_MAX_RETRANSMIT:
            self._transition_message(msg, MessageState.wait_for_send)
            return

        assert msg.state in [MessageState.wait_for_ack, MessageState.wait_for_response]
        if msg.state == MessageState.wait_for_ack:
            msg.status = MessageStatus.ack_timeout
        elif msg.state == MessageState.wait_for_response:
            msg.status = MessageStatus.response_timeout
        self._remove_message(msg)
        msg.transaction_complete_event.set()

    # ------------ asyncore handlers -------------------------------
    def handle_close(self):
        self.close()

    def handle_read(self):
        data_bytes = self.recv(UDP_RECEIVE_BUFFER_SIZE)
        msg = Message.parse(bytearray(data_bytes))
        self._transition_message(msg, MessageState.to_be_received)
        self.fsm_event.set()

    # ------------ asyncore handlers end --------------------------

    def _request(self, method_code, uri_path, confirmable, options, payload=None, timeout=None):
        """ Creates a CoAP request message and puts it in the state machine.
        """
        option = Option(option_number=OptionNumber.uri_path, option_value=uri_path)
        options.append(option)
        message_type = MessageType.confirmable if confirmable else MessageType.non_confirmable
        if timeout is None:
            timeout = self.timeout

        # create a new message
        message_id = self._id_generator.get_next_id()
        msg = Message(message_id=message_id, class_detail=method_code, message_type=message_type, options=options, payload=payload)
        # add to the transmitter queue and wakeup the transmitter to do the processing
        self._transition_message(msg, MessageState.wait_for_send)
        self.fsm_event.set()

        # Wait for the response event to fire.
        if not msg.transaction_complete_event.wait(timeout=self.timeout):
            msg.status = MessageStatus.failed
        return msg

    def get(self, uri_path, confirmable=True, options=[]):
        """ CoAP GET Request """
        return self._request(method_code=MethodCode.get, uri_path=uri_path, confirmable=confirmable, options=options)

    def put(self, uri_path, confirmable=True, options=[], payload=None):
        """ CoAP PUT Request """
        return self._request(method_code=MethodCode.put, uri_path=uri_path, confirmable=confirmable, options=options)

    def post(self, uri_path, confirmable=True, options=[], payload=None):
        """ CoAP POST Request """
        return self._request(method_code=MethodCode.post, uri_path=uri_path, confirmable=confirmable, options=options)

    def delete(self, uri_path, confirmable=True, options=[]):
        """ CoAP DELETE Request """
        return self._request(method_code=MethodCode.delete, uri_path=uri_path, confirmable=confirmable, options=options)
