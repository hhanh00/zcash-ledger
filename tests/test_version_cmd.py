from application_client.command_sender import ZcashCommandSender, InsType


# In this test we check the behavior of the device when asked to provide the app version
def test_version(backend):
    client = ZcashCommandSender(backend)
    rapdu = client.send_request_no_params(InsType.GET_VERSION)

    # Edit this string when the version number is changed
    assert rapdu.data == b"\x01\x00\x01"
