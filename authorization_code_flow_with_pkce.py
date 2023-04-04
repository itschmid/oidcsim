import html
from http.server import HTTPServer
import requests
from urllib import parse

import jwt
import pprint
import re
import webbrowser
import sys

from HttpHandler import OAuthHttpHandler
from OauthTools import code_verifier, code_challenge, get_state_code


# OIDC Konfiguration - Mobile App daher kein Client Secret
realm="testrealm"
client_id="testapp-auth-flow-pkce"
redirect_uri="http://localhost:7080"
scope="openid email profile"

url="https://keycloak_url/realms"


state=get_state_code() 
username = "tester"
password = '..........'

# Einfacher WebServer, als Return wird der Authentication Code zurück geliefert

def browser_auth(params):
    print(60*"-")
    print("1. Init Redirect Web Server")
    with HTTPServer(("0.0.0.0", 7080), RequestHandlerClass=OAuthHttpHandler) as httpd:

        print("2. Start Browser with AUTH-Endpoint URL")
        params = parse.urlencode(params)
        webbrowser.open(f"{url}/{realm}/protocol/openid-connect/auth?{params}")

        httpd.handle_request()
        print("3. Receive Authorization Code from Redirect Server")
        auth_code = httpd.authorization_code

        return auth_code

# CLI - Nicht zu empfehlen
def cli_auth(params):

    # GET Request an Auth Endpoint
    params = parse.urlencode(params)
    resp = requests.get(
        url=f"{url}/{realm}/protocol/openid-connect/auth?{params}",
        allow_redirects=False
    )

    if not resp.status_code == 200:
        sys.exit(1)

    cookie = resp.headers['Set-Cookie']
    cookie = '; '.join(c.split(';')[0] for c in cookie.split(', '))

    page = resp.text
    #ACTION URL auslesen
    form_action = html.unescape(re.search('<form\s+.*?\s+action="(.*?)"', page, re.DOTALL).group(1))

    # POST Request mit Username & Paswort
    resp = requests.post(
        url=form_action,
        data={
            "username": username,
            "password": password,
        },
        headers={"Cookie": cookie},
        allow_redirects=False
    )

    # Aus Response Location als den Redirect mit Parameter auslesen und parsen
    redirect = resp.headers['Location']

    query = parse.urlparse(redirect).query

    redirect_params = parse.parse_qs(query)
    print(60 * "-")

    # Authentifizierungs Code auslesen und übergebem
    auth_code = redirect_params['code'][0]

    return auth_code

def step_1(browser=True):
    print(60*"=")
    print("Start Step 1")
    print(60*"=")

    # Code Verifier erzeugen
    cv = code_verifier()
    print("Generate Code Verifier: %s" % cv)
    # Wert wird mittels Code_Challange_Mehtode SHA256 hashen
    cc = code_challenge(code_verifier=cv)
    print("Generate Code Challenge: %s" % cc)

    #Parameter erzeugen
    params = {
        "response_type": "code",
        "client_id": client_id,
        "scope": "openid",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": cc,
        "code_challenge_method": "S256",
    }

    # Browser oder CLI starten, Authentication Code damit lesen
    if browser:
        auth_code = browser_auth(params=params)
    else:
        auth_code = cli_auth(params=params)

    print(60*"-")
    print("Authentication Code: %s" % auth_code)
    print(60*"-")

    # Authentication Code und Code Verifier an den nächsten Schritt weitergeben
    return auth_code, cv


def step_2(code, cv):
    print(60 * "=")
    print("Start Step 2")
    print(60 * "=")
    print("Authentication Code: %s" % code)
    print(60*"-")
    # Jetzt wird vom Client ein POST-Request zum IDP erstellt.
    # Hier kommen die unten angegebenen Parameter dazu.
    # Wichtig, jetzt wird der Code aus dem vorherigen Step benötigt.

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    data = {
        "code": code,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": cv
    }

    response = requests.post(
        url=f"{url}/{realm}/protocol/openid-connect/token",
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

        print(60*"*")
        print("Access Token: %s" % access_token)
        print("ID Token: %s" % id_token)
        print("Refresh Token %s" % refresh_token )
        print(60 * "*")

    return access_token, id_token

def step_3(access_token, id_token):

    # Im dritten Step, kann jetzt der AccessToken verifiziert werden.
    # Und aus dem AccessToken kann ich jetzt auch Claims auslesen.

    from jwt import PyJWKClient

    # Hier decodiere ich den AccessToken ohne überprüfung.
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

    #x = jwt.decode(access_token, signing_key.key, algorithms=[alg], audience="account")
    #print(x)


if __name__ == "__main__":
    code, cv = step_1(browser=True)
    access_token, id_token = step_2(code, cv)
    step_3(access_token, id_token)




