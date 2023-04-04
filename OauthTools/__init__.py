import base64
import hashlib
import re
import os
import random
import string

def code_verifier():
    # Zufälliger Code Verifier

    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
    code_verifier = re.sub('[^a-zA-Z0-9]+', '', code_verifier)

    return code_verifier

def code_challenge(code_verifier):

    code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
    code_challenge = code_challenge.replace('=', '')

    return code_challenge

def get_state_code():
    state_code = ''.join(random.choices(string.ascii_lowercase + string.digits, k=32))
    return state_code