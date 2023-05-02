from application_client.command_sender import ZcashCommandSender, InsType
import binascii

# In this test we check the behavior of the device when asked to provide the public keys
# The reference values were calculated by the test-gen app

def test_keys(backend):
    client = ZcashCommandSender(backend)
    rapdu = client.send_request_no_params(InsType.GET_PUBKEY)
    assert(binascii.hexlify(rapdu.data) == b"02749c3f99dd136601daa824ecf40ae144c1a7de432bf22dbb23c81c7b6077d431")

    rapdu = client.send_request_no_params(InsType.GET_FVK)
    assert(binascii.hexlify(rapdu.data) == b"e081cdca695f86a98c603a799509d987ad2b1a26487d89e63e2b0c2e0595c6428c720bcc0a54fc5f7076054e3cab13d2f17a0487f1bcd89c298c84700d852ea31bd70862a4598f19b7468dd384c79b9d4d262ac6d01380e97d776fefac3f1fa42ad14d5fab46ff4e0b591a6efc3d704c793607b0088add01f13f9402b4c1a515")

    rapdu = client.send_request_no_params(InsType.GET_OFVK)
    assert(binascii.hexlify(rapdu.data) == b"461c8edb0254123802935845a4240aae706a8ee492d9c325d28f1ab0ef65d7091eeac7a99f6b50bb52e4a63b5b7a86552f455199a51fca4aa1a9b7be50264835f436bb28d989bf9a0ab8986d66633ce06057e482ac4d8dfd2bfa4d84f5f1c204")
