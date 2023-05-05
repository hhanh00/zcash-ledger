import binascii
import json

from application_client.command_sender import ZcashCommandSender
from application_client.response_unpacker import unpack_sized_response

def run_generic_test(client: ZcashCommandSender, test, capsys):
    with capsys.disabled():
        print(test['test_name'])
    for msg in test['messages']:
        client.send_and_check_message(msg)

# In this test we check the behavior of the device when asked to provide the app version
def test_tx_sighash(backend, capsys):
    client = ZcashCommandSender(backend)
    with open("tests/tx-tests.json") as file:
        tests = json.load(file)
        for test in tests:
            run_generic_test(client, test, capsys)

    # # Use the app interface instead of raw interface
    # # Send the TEST_MATH instruction
    # rapdu = client.test_math()
    # # Use an helper to parse the response, assert the values
    # with capsys.disabled():
    #     print(binascii.hexlify(unpack_sized_response(rapdu.data, 32)))
