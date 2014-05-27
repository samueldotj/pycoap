""" Defines all the codes in the CoAP code registry.
    http://tools.ietf.org/html/draft-ietf-core-coap-18#section-12.1
"""

from enum import Enum


class MessageType(int, Enum):
    confirmable = 0
    non_confirmable = 1
    acknowledgment = 2
    reset = 3


class MethodCode(int, Enum):
    get = 1
    post = 2
    put = 3
    delete = 4


class ResponseCodeClass(int, Enum):
    success = 2
    client_error = 4
    server_error = 5


class ResponseCode(int, Enum):
    ok = 0x40
    created = 0x41
    deleted = 0x42
    valid = 0x43
    changed = 0x44
    content = 0x45
    block_continue = 0x5f

    bad_request = 0x80
    unauthorized = 0x81
    bad_option = 0x82
    forbidden = 0x83
    not_found = 0x84
    method_not_allowed = 0x85
    not_acceptable = 0x86
    precondition_failed = 0x8c
    incomplete = 0x88
    request_entity_too_large = 0x8d
    unsupported_content_format = 0x8f

    internal_server_error = 0xa0
    not_implemented = 0xa1
    bad_gateway = 0xa2
    service_unavailable = 0xa3
    gateway_timeout = 0xa4
    proxying_not_supported = 0xa5


class OptionNumber(int, Enum):
    reserved = 0
    if_match = 1
    uri_host = 3
    etag = 4
    if_none_match = 5
    uri_port = 7
    location_path = 8
    observe = 6
    uri_path = 11
    content_format = 12
    max_age = 14
    uri_query = 15
    accept = 17
    location_query = 20
    block2 = 23
    block1 = 27
    proxy_uri = 35
    size1 = 36
    proxy_scheme = 39
    max = 1000


class ContentFormat(int, Enum):
    text = 0
    link = 40
    xml = 41
    octet_stream = 42
    exi = 47
    json = 50
