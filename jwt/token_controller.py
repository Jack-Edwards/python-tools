import datetime
import uuid
from .token_model import TokenModel

class TokenController:
    def __init__(
        self,
        token_id,
        token_issuer,
        token_subject,
        token_audience,
        token_expiration,
        token_created
    ):

        #  Public properties
        self.id = token_id
        self.iss = token_issuer
        self.sub = token_subject
        self.aud = token_audience
        self.exp = token_expiration
        self.iat = int(datetime.datetime.strptime(
            token_created, '%Y-%m-%d %H:%M:%S').timestamp())

        #  Private properties
        self._payload = None
        self._token = None

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, value):
        if not self._payload:
            self._payload = value
        else:
            raise ValueError('Cannot overwrite payload')

    #  Return the TokenController properties in payload format
    def generate_payload(self):
        return {
                'iss': self.iss,
                'sub': self.sub,
                'aud': self.aud,
                'exp': self.exp,
                'iat': self.iat,
                'jti': self.id
        }

    @property
    def token(self):
        return self._token

    @token.setter
    def token(self, value):
        if not self._token:
            self._token = value 
        else:
            raise ValueError('Cannot overwrite token')
                   
    #  Generate a new token
    def new_token(self, key, algorithm):
        if self.payload:
            return TokenModel().encode(self.payload, key, algorithm)
        else:
            raise ValueError('Cannot create new token before payload has been set')

    #  Decode the token
    def decode_token(self, key, algorithm):
        if self._token:
            return TokenModel().decode(self.token, key, algorithm)
        else:
            raise ValueError('Cannot decode token before token has been set')
