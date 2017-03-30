""" shsmd utility methods
"""
from binascii import Error as BinasciiError
from nacl.encoding import Base64Encoder
from nacl.signing import SignedMessage
from nacl.bindings import crypto_sign_BYTES
from flask_restful import abort

def reconstruct_signed_message(signed_message):
    """ hacky method for reconstructing signed messages as
        a PyNaCl SignedMessage object.
    """

    try:
        tmp_signed_message = Base64Encoder.decode(signed_message)
        recon_signed_message = SignedMessage._from_parts(
            tmp_signed_message[:crypto_sign_BYTES],
            tmp_signed_message[crypto_sign_BYTES:],
            tmp_signed_message)
        if len(recon_signed_message.message) == 0:
            raise TypeError
    except (TypeError, BinasciiError):
        abort(400,
              message="The provided signed_message is not valid.")

    return recon_signed_message
