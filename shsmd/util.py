""" shsmd
"""
from base64 import b64decode
from nacl.encoding import RawEncoder
from nacl.signing import SignedMessage
import nacl.utils
from flask_restful import abort

def reconstruct_signed_message(signed_message):
    """ hacky method for reconstructing signed messages as
        a PyNaCl SignedMessage object.
    """

    tmp_encoder = RawEncoder
    try:
        tmp_signed_message = tmp_encoder.encode(b64decode(signed_message))
        recon_signed_message = SignedMessage._from_parts(
            tmp_encoder.encode(
                tmp_signed_message[:nacl.bindings.crypto_sign_BYTES]),
            tmp_encoder.encode(
                tmp_signed_message[nacl.bindings.crypto_sign_BYTES:]),
            tmp_signed_message)
    except TypeError:
        abort(400,
              message="The provided signed_message is not valid.")

    return recon_signed_message
