from http.server import BaseHTTPRequestHandler
from urllib import parse

class OAuthHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(self.headers)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.wfile.write("<script type=\"application/javascript\">window.close();</script>".encode("UTF-8"))

        parsed = parse.urlparse(self.path)
        qs = parse.parse_qs(parsed.query)
        print(60*".")
        print(self.path)
        print(60 * ".")

        self.server.authorization_code = qs["code"][0]