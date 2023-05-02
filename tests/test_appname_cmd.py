from application_client.command_sender import ZcashCommandSender, InsType
from application_client.response_unpacker import unpack_ascii

# In this test we check that the GET_APP_NAME replies the application name
def test_app_name(backend):
    client = ZcashCommandSender(backend)
    response = client.send_request_no_params(InsType.GET_APP_NAME)
    # Assert that we have received the correct appname
    assert unpack_ascii(response.data) == "Zcash"
