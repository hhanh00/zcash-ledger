import binascii
from application_client.boilerplate_command_sender import BoilerplateCommandSender
from application_client.boilerplate_response_unpacker import unpack_bn_response

# In this test we check the behavior of the device when asked to provide the app version
def test_math(backend, capsys):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # Send the TEST_MATH instruction
    rapdu = client.test_math()
    # Use an helper to parse the response, assert the values
    with capsys.disabled():
        print(binascii.hexlify(unpack_bn_response(rapdu.data)))
    assert(false)
    