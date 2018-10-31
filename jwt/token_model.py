import base64
import hashlib
import hmac
import json

class TokenModel:
    def __init__(self):
        self.header_type = 'JWT'
        self.empty_payload = {
            'iss': None, # Issuer
            'sub': None, # Subject
            'aud': None, # Audience
            'qsh': None, # Query string hash
            'exp': None, # Expiration, in Unix time
            'nbf': None, # Not before time; token is not valid until this datetime, in Unix time
            'iat': None, # Issue at time, in Unix time
            'jti': None  # Unique identifier for the token
        }
        self.supported_algorithms = [
            'HS256'
        ]                       

    #  Create a base64-encoded json object
    #  Return format: 'header.payload.signature'
    def encode(self, payload, key, algorithm):
        if type(payload) != dict:
            raise TypeError('Payload must be a dict') 

        header = {
            'alg': algorithm,
            'typ': self.header_type
        }

        header = base64.urlsafe_b64encode(json.dumps(header).encode('utf-8')).decode()
        payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode()

        message = '{}.{}'.format(header, payload)
        signature = self.make_signature(message, key, algorithm)

        return '{}.{}.{}'.format(header, payload, signature)


    #  Decode the passed in base64-encoded json object
    #  Expected token format: 'header.payload.signature'
    def decode(self, token, key, algorithm):
        if type(token) != str:
            raise TypeError('Token must be a str')

        if len(token.split('.')) != 3:
            raise ValueError('Token must have 3 segments, separated with periods')

        if algorithm not in self.supported_algorithms:
            raise ValueError('Algorithm not supported')

        jwt_header, jwt_payload, jwt_signature = token.split('.')
        py_header = json.loads(base64.urlsafe_b64decode(jwt_header).decode()) # not important?
        py_payload = json.loads(base64.urlsafe_b64decode(jwt_payload).decode())
        
        message = '{}.{}'.format(jwt_header, jwt_payload)
        derived_signature = self.make_signature(message, key, algorithm)

        if hmac.compare_digest(jwt_signature, derived_signature):
            return {'verified': True, 'header': py_header, 'payload': py_payload}
        else:
            return {'verified': False, 'header': py_header, 'payload': py_payload}
        

    def make_signature(self, message, key, algorithm):
        if algorithm not in self.supported_algorithms:
            raise ValueError('Algorithm not supported')

        if algorithm == 'HS256':
            return hmac.new(key.encode('utf-8'), message.encode('utf-8'), hashlib.sha256).hexdigest()


    def verify_signature(self, signature1, signature2, algorithm):
        if algorithm not in self.supported_algorithms:
            raise ValueError('Algorithm not supported')

        if algorithm == 'HS256':
            return hmac.compare_digest(signature1, signature2)
