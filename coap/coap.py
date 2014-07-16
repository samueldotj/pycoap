""" This file implements passing Coap Requests and Responses between server and client.

There is a simple state machine which maintains the message states such as ACK, RST. This state machine runs as
a separate thread(_fsm_loop).
"""

import gevent.monkey
gevent.monkey.patch_all()

import socket
import urlparse
import logging

import gevent
import gevent.event
import gevent.socket

from code_registry import MethodCode, MessageType, OptionNumber, ResponseCodeClass
from message import Message, Option, MessageState, MessageStatus, CoapOption, \
    SequenceMessageIdGenerator, SequenceTokenGenerator, COAP_MAX_RETRANSMIT, COAP_BLOCK_MAX_SIZE
import traceback

COAP_DEFAULT_PORT = 5683
UDP_RECEIVE_BUFFER_SIZE = 2048
DEFAULT_REQUEST_TIMEOUT = 5


""" Implemented CoAP options, any other options would result in reset message(if it is a critical option)."""
implemented_options = [
    OptionNumber.observe,
    OptionNumber.uri_host,
    OptionNumber.uri_port,
    OptionNumber.uri_path,
    OptionNumber.content_format,
    OptionNumber.uri_query,
    OptionNumber.block1,
    OptionNumber.block2,
]

coap_log = logging.getLogger('coap')


def _extract_stack(count=5):
    """
    Helper function to extract the function stack.
    :param count: Number of stack(last most) to extract.
    :return: function names as string.
    """
    result = ''
    for t in traceback.extract_stack()[:count]:
        result += '{0}->'.format(t[2])
    return result


class Coap():
    """ Manages CoAP request to a server."""
    def __init__(self, host, port=COAP_DEFAULT_PORT, timeout=DEFAULT_REQUEST_TIMEOUT,
                 message_id_generator=SequenceMessageIdGenerator(),
                 token_generator=SequenceTokenGenerator(token_length=2)):

        # decode the given host name and create a socket out of it.
        af, socktype, proto, canonname, sa = gevent.socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)[0]
        self._socket = gevent.socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self._socket.connect(sa)

        self.timeout = timeout

        self._id_generator = message_id_generator
        self._token_generator = token_generator

        # CoAP messages are maintained in different lists based on the message state.
        self.message_queues = {
            MessageState.init: [],
            MessageState.to_be_received: [],
            MessageState.wait_for_send: [],
            MessageState.wait_for_ack: [],
            MessageState.wait_for_response: [],
            MessageState.wait_for_free: [],
            MessageState.wait_for_updates: []
        }
        # A event to continue state machine processing.
        self.fsm_event = gevent.event.Event()

        # If this flag is set then the threads created by this class should exit.
        self._stop_requested = False

        # Greenlets created
        self._greenlets = [gevent.spawn(self._socket_receive_loop),
                           gevent.spawn(self._fsm_loop)]

    def destroy(self):
        """ Stops the threads started by this class. """
        coap_log.debug('Stopping threads')
        self._stop_requested = True
        self._socket.close()
        self.fsm_event.set()

        gevent.joinall(self._greenlets)

    def _socket_receive_loop(self):
        """ Receives data from socket forever.   """
        while True:
            if self._stop_requested:
                return
            try:
                data_bytes = self._socket.recv(UDP_RECEIVE_BUFFER_SIZE)
                if self._stop_requested:
                    return
            except:
                pass
            else:
                msg = Message.parse(bytearray(data_bytes))
                self._transition_message(msg, MessageState.to_be_received)
                self.fsm_event.set()


    def _get_next_timeout(self):
        """ Returns the when the next timeout event should fire(in seconds).
        Since the message_queue is arranged in the same order as the messages are arrived, the last entry in the message
        should have less timeout value. So this function will take the least of timeout from last element in the list.
        """
        result = 0
        for state in [MessageState.wait_for_ack, MessageState.wait_for_response, MessageState.wait_for_send]:
            if len(self.message_queues[state]) > 0:
                msg = self.message_queues[state][-1]
                timeout = msg.get_timeout()
                if timeout < result or result == 0:
                    result = timeout

        # Check observe message's max-age
        for msg in self.message_queues[MessageState.wait_for_updates]:
            timeout = msg.get_timeout()
            if timeout < result or result == 0:
                result = timeout

        return result

    def _fsm_loop(self):
        """ The main state machine loop.
        The loop would block if there nothing to be done.
        """
        while True:
            # Sleep until something need to be done(either new messages needs to be send or timeout)
            timeout = self._get_next_timeout()
            coap_log.debug('FSM - Waiting for event with timeout {0}'.format(timeout))
            if timeout > 0:
                self.fsm_event.wait(timeout)
            else:
                self.fsm_event.wait()
            self.fsm_event.clear()

            # Receive messages
            messages = self.message_queues[MessageState.to_be_received]
            if len(messages) > 0:
                coap_log.debug('FSM - Receiving {0} messages'.format(len(messages)))
            for msg in messages:
                self._receive_message(msg)

            # Send all messages in the send queue
            messages = self.message_queues[MessageState.wait_for_send]
            if len(messages) > 0:
                coap_log.debug('FSM - Sending {0} messages'.format(len(messages)))
            for msg in messages:
                self._send_message(msg)

            # Handle timeouts
            for state in [MessageState.wait_for_ack, MessageState.wait_for_response, MessageState.wait_for_send]:
                for msg in reversed(self.message_queues[state]):
                    # check how long we have before the timeout.
                    if msg.get_timeout() > 0:
                        # since the list ordered by the message arrival there is no need to check further
                        break
                    self._timeout_message(msg)

            # Handle maxAge of observe values, if maxage is reached, we need to remove these values from wait_for_updates queue
            for msg in self.message_queues[MessageState.wait_for_updates]:
                if msg.get_timeout() > 0:
                    continue
                self._timeout_message(msg)

            if self._stop_requested:
                coap_log.debug('FSM - Terminating because stop requested')
                return

    def _find_message(self, token, message_id, state):
        """ Returns the message with given token and message_id.

        Searches for a matching message in the given message list(based on state).
        If found it returns the list index and message itself.
        If no match found then None is returned.
        """
        assert token is not None or message_id is not None
        for idx, msg in enumerate(self.message_queues[state]):
            if (token is None or token == msg.token) and (message_id is None or message_id == msg.message_id):
                return idx, msg
        return None, None

    def _remove_message(self, msg):
        """ Removes the given message from the state machine.

        Searches given message in the state machine lists.
        If found removes the message from the state machine and returns True.
        If no match found then returns False.
        """
        idx, unused = self._find_message(msg.token, msg.message_id, msg.state)
        if idx is not None:
            coap_log.debug('From state {0} removing message {1} :: {2}'.format(msg.state, msg.message_id, _extract_stack()))
            del self.message_queues[msg.state][idx]
            return True

        return False

    def _transition_message(self, msg, new_state):
        """ Transitions a message to a new state.

        Changes the message state and also moves the message new state list.
        If the message is not found in the state machine then it would throw an exception.
        """
        if msg.state == MessageState.init or self._remove_message(msg):
            msg.change_state(new_state)
            coap_log.debug('Putting message {0} in state {1} :: {2}'.format(msg.message_id, msg.state, _extract_stack()))
            self.message_queues[new_state].append(msg)
        else:
            raise Exception('Invalid message({0}) state {1} new_state {2}'.format(msg.message_id, msg.state, new_state))

    def _receive_ack(self, msg):
        """Receives an ACK and transitions message's state based on that.
        """
        self._remove_message(msg)

        idx, parent_msg = self._find_message(token=None, message_id=msg.message_id, state=MessageState.wait_for_ack)
        if parent_msg is None:
            coap_log.warning('ACK received but no matching message found - Sending RESET')
            reset_msg = Message(message_id=msg.message_id, message_type=MessageType.reset)
            self._socket.send(reset_msg.build())
            return
        if parent_msg.type != MessageType.confirmable:
            coap_log.error('ACK received for NON-CONFIRMABLE message - Ignoring')
            return

        self._transition_message(parent_msg, MessageState.wait_for_response)

        if msg.class_code == 0 and msg.class_detail == 0:
            # if this is empty message send just for ACK we are already done.
            coap_log.debug('Separate ACK received')
            return

        #coap_log.debug('Piggybacked RESPONSE {0}'.format(str(msg)))
        if msg.has_observe_option():
            self._receive_observe(parent_msg, msg)
            return

        # This message has a piggybacked response, so receive it.
        self._receive_response(parent_msg, msg)

    def _receive_response(self, req_msg, resp_msg):
        """ Receives a response
        """
        self._remove_message(req_msg)
        req_msg.server_reply_list.append(resp_msg)

        # if error received then fail immediately.
        if resp_msg.class_code != ResponseCodeClass.success:
            req_msg.transaction_complete_event.set()
            return

        # handle block options separately.
        if self._receive_block_response(req_msg, resp_msg):
            return

        # wake up threads waiting for this message
        req_msg.transaction_complete_event.set()

    def _receive_block_response(self, req_msg, resp_msg):
        """ Receives a response with block option(s) set.
            Returns True if the message is processed and no more processing is required.
        """
        block1_options = resp_msg.find_option(OptionNumber.block1)
        block2_options = resp_msg.find_option(OptionNumber.block2)
        if len(block1_options) == 0 and len(block2_options) == 0:
            return False

        if resp_msg.class_code != ResponseCodeClass.success:
            coap_log.error('BLOCK message with error. {0}.{1}'.format(resp_msg.class_code, resp_msg.class_detail))
            return False

        if len(block1_options) > 1:
            coap_log.warning('Multiple BLOCK1 options found in response - ignoring everything else but first')
        if len(block2_options) > 1:
            coap_log.warning('Multiple BLOCK2 options found in response - ignoring everything else but first')

        if len(block1_options) > 0 and len(block2_options) > 0:
            coap_log.error('BLOCK1 + BLOCK2 in a single response is not yet implemented.')
        elif len(block1_options) > 0:
            self._receive_block1_response(req_msg, resp_msg, block1_options[0])
        elif len(block2_options) > 0:
            self._receive_block2_response(req_msg, resp_msg, block2_options[0])

        return True

    def _receive_block1_response(self, req_msg, resp_msg, req_block1_option):
        """ Handles a Block1 option in the response message
        """
        last_block_number, m_bit, pref_max_size = Option.block_value_decode(req_block1_option.value)
        coap_log.debug('Block1 response: block_number={0} m_bit={1} size={2}'.format(last_block_number, m_bit, pref_max_size))

        block_number = last_block_number + 1
        req_msg.block1_preferred_size = pref_max_size
        payload_size = len(req_msg.block1_payload)
        total_blocks = (payload_size / pref_max_size) + 1
        more = block_number < total_blocks
        payload_start = last_block_number * pref_max_size
        cur_payload = req_msg.block1_payload[payload_start:payload_start + pref_max_size]
        if ((last_block_number * pref_max_size) + len(cur_payload)) <= payload_size:
            #send request with next post/put request, reuse the same message(change block1 option and msg_id)
            req_msg.remove_option(OptionNumber.block1)
            req_msg.remove_option(OptionNumber.block2)
            block1_option = Option(OptionNumber.block1, Option.block_value_encode(block_number, more, pref_max_size))
            req_msg.add_option(block1_option)

            req_msg.set_payload(cur_payload)

            req_msg.recycle(self._id_generator.get_next_id())
            self._transition_message(req_msg, MessageState.wait_for_send)
        else:
            # All blocks are send, so lets wake up the caller
            req_msg.transaction_complete_event.set()

    def _receive_block2_response(self, req_msg, resp_msg, block2_option):
        """ Handles a Block2 option in the response message
        """
        block_number, more, size = Option.block_value_decode(block2_option.value)
        coap_log.debug('Block2 response: block_number={0} m_bit={1} size={2}'.format(block_number, more, size))

        if more:
            #send request to fetch next block, reuse the same message(change block2 option and msg_id)
            req_msg.remove_option(OptionNumber.block1)
            req_msg.remove_option(OptionNumber.block2)
            block2_option = Option(OptionNumber.block2, Option.block_value_encode(block_number + 1, False, size))
            req_msg.add_option(block2_option)

            req_msg.recycle(self._id_generator.get_next_id())
            self._transition_message(req_msg, MessageState.wait_for_send)
        else:
            # All blocks are received, so lets wake up the caller
            req_msg.transaction_complete_event.set()

    def _receive_observe(self, req_msg, observe_msg):
        """ Receives a observe message - invokes the callback function and resets the timeout(age).
        """

        # lets have only the last observed message (otherwise the client would run out space soon)
        req_msg.server_reply_list = [observe_msg]
        # Invoke if anybody waiting for the message to arrive.
        req_msg.transaction_complete_event.set()

        self._transition_message(req_msg, MessageState.wait_for_updates)
        req_msg.age = observe_msg.get_age_from_option()
        if req_msg.callback:
            if observe_msg.payload:
                payload = observe_msg.payload.value
            else:
                payload = ''
            req_msg.callback(payload, observe_msg)
        else:
            coap_log.error('OBSERVE message received but callback is missing')
        self._remove_message(observe_msg)

    def _receive_message(self, msg):
        """ Handles a received COAP message.

            The state machine calls this function to process a received a CoAP message.
        """
        coap_log.info('Received CoAP message {0}'.format(str(msg)))

        # Check if any unimplemented option appears in the message.
        # If there is any critical unsupported message we should send a reset message.
        unsupported_options = [opt for opt in msg.coap_option if opt.option_number not in implemented_options]
        unsupported_critical_options = [opt for opt in unsupported_options if opt.option_number & 1]
        if len(unsupported_critical_options) > 0:
            for opt in unsupported_critical_options:
                coap_log.warning('Unsupported critical option {0}'.format(opt.option_number))
            coap_log.warning('Sending RESET for {0}'.format(str(msg)))
            reset_msg = Message(message_id=msg.message_id, message_type=MessageType.reset)
            self._socket.send(reset_msg.build())
            return

        has_observe_option = msg.has_observe_option()

        # If we got reset message in response to a request, then handle it accordingly
        if msg.type == MessageType.reset:
            self._remove_message(msg)
            coap_log.error('RESET handling is not yet implemented')
            return

        # If ACK is received, do the necessary processing for that first.
        if msg.type == MessageType.acknowledgment:
            self._receive_ack(msg)
            return

        assert msg.type in [MessageType.confirmable, MessageType.non_confirmable]

        # At this point this message can be a REQUEST or a separate response or a notify for  resource being observed.
        idx, req_msg = self._find_message(token=msg.token, message_id=None, state=MessageState.wait_for_response)
        if req_msg is None and not has_observe_option:
            # This is a new REQ
            coap_log.error('REQUEST not implemented yet {0}'.format(str(msg)))
            return

        # We got the response as separate message, first send ACK if needed.
        if msg.type == MessageType.confirmable:
            ack_msg = Message(message_id=msg.message_id, message_type=MessageType.acknowledgment, token=msg.token)
            self._socket.send(ack_msg.build())

        #if message has observe option set, the server will send updates, So copy the message into wait_for_updates queue
        if has_observe_option:
            if req_msg is None:
                idx, req_msg = self._find_message(token=msg.token, message_id=None, state=MessageState.wait_for_updates)

            if req_msg is None:
                coap_log.error('OBSERVE message received for but not observing token {0}'.format(msg.token))
                #TODO - send a reset message
                return
            self._receive_observe(req_msg, msg)
            return

        self._receive_response(req_msg, msg)

    def _send_message(self, msg):
        """ Process a message which needs to be send out.

            Converts the given message in to bytestream and then sends it over the socket.
            Then places the message in appropriate wait queue to wait for response.
        """
        coap_log.info('Sending CoAP message {0}'.format(str(msg)))

        #TODO - implement response sending.
        assert msg.class_code == 0

        self._socket.send(msg.build())
        if msg.type == MessageType.confirmable:
            self._transition_message(msg, MessageState.wait_for_ack)
        else:
            self._transition_message(msg, MessageState.wait_for_response)

    def _timeout_message(self, msg):
        """ Timeout given message by requeueing it.
        """
        assert msg.get_timeout() <= 0
        if msg.retransmission_counter < COAP_MAX_RETRANSMIT:
            coap_log.info('Retransmitting message {0}'.format(str(msg)))
            self._transition_message(msg, MessageState.wait_for_send)
            return

        assert msg.state in [MessageState.wait_for_ack, MessageState.wait_for_response, MessageState.wait_for_updates]
        if msg.state == MessageState.wait_for_ack:
            msg.status = MessageStatus.ack_timeout
        elif msg.state == MessageState.wait_for_response:
            msg.status = MessageStatus.response_timeout
        elif msg.state == MessageState.wait_for_updates:
            msg.status = MessageStatus.observe_timeout

        coap_log.error('TIMEOUT - Removing message {0}'.format(str(msg)))
        self._remove_message(msg)
        msg.transaction_complete_event.set()

    def _send_request(self, method_code, uri_path, confirmable, options, payload=None, timeout=None,
                      block1_size=128, token=None, callback=None):
        """ Creates a CoAP request message and puts it in the state machine.
        """
        if options is None:
            options = []
        url_parsed = urlparse.urlparse(uri_path)
        uri_path = url_parsed.path
        for path_segment in uri_path.split('/'):
            option = Option(option_number=OptionNumber.uri_path, option_value=path_segment)
            options.append(option)
        if url_parsed.query:
            option = Option(option_number=OptionNumber.uri_query, option_value=url_parsed.query)
            options.append(option)

        message_type = MessageType.confirmable if confirmable else MessageType.non_confirmable

        #Use default block size if no preferred block size is provided.
        if payload and len(payload) > COAP_BLOCK_MAX_SIZE and block1_size == 0:
            block1_size = 128

        # Add block1 option if required
        if method_code in [MethodCode.post, MethodCode.put] and payload and len(payload) > block1_size:
            option = Option(OptionNumber.block1, Option.block_value_encode(0, len(payload) > block1_size, block1_size))
            options.append(option)

        # create a new message
        message_id = self._id_generator.get_next_id()
        tok = token
        if tok is None:
            tok = self._token_generator.get_next_token()
        msg = Message(message_id=message_id, class_detail=method_code, message_type=message_type, options=options,
                      payload=payload, block1_size=block1_size, token=tok)
        msg.callback = callback

        # add to the transmitter queue and wakeup the transmitter to do the processing
        msg.transaction_complete_event.clear()
        self._transition_message(msg, MessageState.wait_for_send)
        self.fsm_event.set()

        return msg

    def _request(self, method_code, uri_path, confirmable, options, payload=None, timeout=None,
                 block1_size=128, token=None, callback=None):
        """ Sends a CoAP message and waits for the ACK/response. """
        msg = self._send_request(method_code=method_code, uri_path=uri_path, confirmable=confirmable, options=options,
                                 payload=payload, timeout=timeout, block1_size=block1_size, token=token, callback=callback)

        # Wait for the response event to fire.
        if not msg.transaction_complete_event.wait(timeout):
            msg.status = MessageStatus.failed

        return CoapResult(request_msg=msg, response_msg=msg.server_reply_list[-1])

    def get(self, uri_path, confirmable=True, options=None):
        """ CoAP GET Request """
        return self._request(method_code=MethodCode.get, uri_path=uri_path, confirmable=confirmable, options=options)

    def put(self, uri_path, confirmable=True, options=None, payload=None):
        """ CoAP PUT Request """
        return self._request(method_code=MethodCode.put, uri_path=uri_path, confirmable=confirmable, options=options, payload=payload)

    def post(self, uri_path, confirmable=True, options=None, payload=None):
        """ CoAP POST Request """
        return self._request(method_code=MethodCode.post, uri_path=uri_path, confirmable=confirmable, options=options, payload=payload)

    def delete(self, uri_path, confirmable=True, options=None):
        """ CoAP DELETE Request """
        return self._request(method_code=MethodCode.delete, uri_path=uri_path, confirmable=confirmable, options=options)

    def observe(self, uri_path, callback):
        """ Start Observing a coap url

        Callback will be invoked whenever the server sends a notification.
        It will provided with payload and msg as argument.
        """
        options = [CoapOption(option_number=OptionNumber.max_age, option_value='\x3C'),
                   CoapOption(option_number=OptionNumber.observe, option_value='\x00')]
        msg = self._request(MethodCode.get, uri_path, confirmable=True, options=options, callback=callback)

    def stop_observe(self, uri_path):
        """ Stop Observing the specified CoAP url """
        obs_msg = None
        for msg in self.message_queues[MessageState.wait_for_updates]:
            if msg.url == uri_path:
                obs_msg = msg

        if obs_msg is None:
            return False

        coap_log.info('Cancelling observe - {0}'.format(uri_path))

        # send stop request(get without observe option) and wait for it.
        self._request(method_code=MethodCode.get, uri_path=uri_path, confirmable=True, options=None)
        # Also send a RESET message.
        # According to RFC the above message itself if enough but some servers are not respecting it.
        reset_msg = Message(message_id=obs_msg.message_id, message_type=MessageType.reset, token=obs_msg.token)
        self._socket.send(reset_msg.build())
        self._remove_message(obs_msg)

        return True


class CoapResult(object):
    """ Represents result of a CoAP Request
    """
    def __init__(self, request_msg, response_msg):
        assert request_msg
        self.request_msg = request_msg
        self.response_msg = response_msg
        self.status = request_msg.status
        if response_msg:
            self.response_code = response_msg.class_code << 5 | response_msg.class_detail
            self.payload = bytearray()
            for msg in request_msg.server_reply_list:
                if msg.payload != '':
                    self.payload += bytearray(msg.payload.value)
            self.options = response_msg.coap_option
        else:
            self.response_code = 0
            self.payload = bytearray()
            self.options = []


def request(coap_url, method=MethodCode.get, payload=None):
    """ A wrapper to make a single request.

        Example - coap.request('coap://coap.me/hello')
    """
    url = urlparse.urlparse(coap_url)
    if url.scheme.lower() not in ['coap', '']:
        raise Exception('Not a CoAP URI')

    coap = Coap(host=url.hostname, port=url.port if url.port else COAP_DEFAULT_PORT)
    uri_path = url.path[1:]
    if url.query:
        uri_path += '?' + url.query
    if method == MethodCode.get:
        result = coap.get(uri_path)
    elif method == MethodCode.post:
        result = coap.post(uri_path, payload=payload)
    elif method == MethodCode.put:
        result = coap.put(uri_path, payload=payload)
    elif method == MethodCode.delete:
        result = coap.delete(uri_path)
    coap.destroy()

    return result
