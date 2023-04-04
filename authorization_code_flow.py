import webbrowser
from http.server import HTTPServer
import requests
from urllib import parse

import jwt
import pprint
import sys
import logging


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

from HttpHandler import OAuthHttpHandler
from OauthTools import get_state_code

# OIDC Konfiguration
realm="testrealm"
client_id="testapp-auth-flow"
client_secret=".........."
redirect_uri="http://localhost:7080"
scope="openid email profile"

url="https://keycloak_url/realms"

state=get_state_code()

def step_1():
    print(60 * "=")
    print("Start Step 1")
    print(60 * "=")
    # WebServer wird gestartet

    # Starte Webserver
    print(60 * "-")
    print("1. Init Redirect Web Server")
    with HTTPServer(("0.0.0.0", 7080), RequestHandlerClass=OAuthHttpHandler) as httpd:

        # Parameter erzeugen
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state
        }

        # Browser mit URL zum Auth Entpoint und Parameter starten
        print("2. Start Browser with AUTH-Endpoint URL")
        params = parse.urlencode(params)
        webbrowser.open(f"{url}/{realm}/protocol/openid-connect/auth?{params}")

        # Response abfangen und Authorisation-Code filter
        httpd.handle_request()
        print("3. Receive Authorization Code from Redirect Server")
        auth_code = httpd.authorization_code

        # Authorization Code weitergeben
        return auth_code

def step_2(code):
    print(60 * "=")
    print("Start Step 2")
    print(60 * "=")
    print("Authentication Code: %s" % code)
    print(60 * "-")
    # Jetzt wird vom Client ein POST-Request zum IDP erstellt.
    # Hier kommen die unten angegebenen Parameter dazu.
    # Wichtig, jetzt wird der Code aus dem vorherigen Step benötigt.

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Parameter erzeugen
    data = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code"
    }

    # POST Request an Token Endpoint
    response = requests.post(
        f"{url}/{realm}/protocol/openid-connect/token",
        data=data,
        verify=True,
        headers=headers
        )

    # Vom IDP bekommt der Client jetzt einen Accesstoken für den User zurück
    if not response.status_code == 200:
        print("ERROR: STATUS_CODE %s" % response.status_code)
        sys.exit(1)

    resp_js = response.json()
    if "id_token" in resp_js:
        print("Logging erfolgreich")

        access_token = resp_js["access_token"]
        id_token = resp_js["id_token"]
        refresh_token = resp_js["refresh_token"]

        print(60 * "*")
        print("Access Token: %s" % access_token)
        print("ID Token: %s" % id_token)
        print("Refresh Token %s" % refresh_token)
        print(60 * "*")

        # Hier oder im Step 3 müsste man jetzt noch den Token genauer überprüfen.
    return access_token, id_token

def step_3(access_token, id_token):

    # Im dritten Step, kann jetzt der AccessToken verifiziert werden.
    # Und aus dem AccessToken kann ich jetzt auch Claims auslesen.

    from jwt import PyJWKClient

    # Hier decodiere ich den AccessToken ohne Überprüfung.
    jwt_token = jwt.api_jwt.decode_complete(access_token, options={"verify_signature": False})
    print(60*"-")
    print("ACCES TOKEN")
    print(60*"-")
    pprint.pprint(jwt_token)
    
    print(60*"-")
    print("ID TOKEN")
    print(60*"-")
    jwt_id_token = jwt.api_jwt.decode_complete(id_token, options={"verify_signature": False})
    pprint.pprint(jwt_id_token)



    # Ich ziehe mir hier aus dem JWT Header "alg" und "kid"
    alg = jwt_token['header']['alg']
    kid = jwt_token['header']['kid']

    # Jetzt hole ich mir vom Keycloak den Certs und prüfe damit den JWT Token.
    jwts_url = f"{url}/{realm}/protocol/openid-connect/certs"

    jwks_client = PyJWKClient(jwts_url)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token)

    # Wird mir kein Fehlerausgegeben ist der JWT korrekt.
    '''
    x = jwt.decode(access_token, 
                   key=signing_key.key, 
                   algorithms=[alg], 
                   audience="testapp-auth-flow", 
                   issuer="https://keycloak_url/realms/testrealm",
                   options={"require": ["exp", "iss", "sub"]})
    print(x)
    '''

if __name__ == "__main__":
    code = step_1()
    access_token, id_token = step_2(code)
    step_3(access_token, id_token)




