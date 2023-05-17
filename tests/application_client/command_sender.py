from enum import IntEnum
from typing import Generator, List, Optional
import binascii
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class InsType(IntEnum):
    GET_VERSION = 0x03
    GET_APP_NAME = 0x04
    GET_PUBKEY = 0x06
    GET_FVK = 0x07
    GET_OFVK = 0x08
    GET_PROOF_KEY = 0x09
    HAS_ORCHARD = 0x0A
    INIT_TX = 0x10

def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x:x + max_size] for x in range(0, len(message), max_size)]

class ZcashCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    # def get_app_and_version(self) -> RAPDU:
    #     return self.backend.exchange(cla=0xB0,  # specific CLA for BOLOS
    #                                  ins=0x01,  # specific INS for get_app_and_version
    #                                  p1=P1.P1_START,
    #                                  p2=P2.P2_LAST,
    #                                  data=b"")
    #
    #
    # def get_version(self) -> RAPDU:
    #     return self.backend.exchange(cla=CLA,
    #                                  ins=InsType.GET_VERSION,
    #                                  p1=P1.P1_START,
    #                                  p2=P2.P2_LAST,
    #                                  data=b"")

    def send_request_no_params(self, ins) -> RAPDU:
        return self.backend.exchange(cla=CLA,
                                    ins=ins,
                                    p1=0,
                                    p2=0,
                                    data=b"")

    def send_and_check_message(self, msg):
        req = binascii.unhexlify(msg['req'])
        req_type = req[1]
        expected = binascii.unhexlify(msg['rep'])[:-2] # skip status code
        rep = self.backend.exchange_raw(data=req).data
        if req_type != InsType.INIT_TX: # INIT_TXT returns a random seed that changes every time
            assert (rep == expected)

    def has_orchard(self) -> bool:
        rep = self.backend.exchange(cla=CLA,
                                    ins=InsType.HAS_ORCHARD,
                                    p1=0,
                                    p2=0,
                                    data=b"")
        data = rep.data
        data[0] == 1

