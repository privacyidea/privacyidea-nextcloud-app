"""Minimal stand-in for the privacyIDEA /validate/check endpoint, used by run.sh.

It accepts the OTP 123456 for every user and rejects every other value. The app
sends multipart/form-data, so the handler parses that as well as url-encoded
bodies.

    python3 mock_privacyidea.py <bind-address> <port>
"""
import json
import sys
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

VALID_OTP = '123456'


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        content_type = self.headers.get('Content-Type', '')
        if content_type.startswith('multipart/form-data'):
            message = BytesParser(policy=HTTP).parsebytes(b'Content-Type: ' + content_type.encode() + b'\r\n\r\n' + body)
            params = {part.get_param('name', header='content-disposition'): part.get_content()
                      for part in message.iter_parts()}
        else:
            params = {key: values[0] for key, values in parse_qs(body.decode('utf-8', 'replace')).items()}

        if not self.path.startswith('/validate/check'):
            self.reply(404, {'result': {'status': False, 'error': {'code': 404, 'message': 'not mocked'}}})
            return
        accepted = params.get('pass') == VALID_OTP
        self.reply(200, {
            'result': {'status': True, 'value': accepted, 'authentication': 'ACCEPT' if accepted else 'REJECT'},
            'detail': {'message': 'matching 1 tokens' if accepted else 'wrong otp value', 'serial': 'MOCK0001'},
        })

    def reply(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write('%s %s\n' % (self.address_string(), format % args))


if __name__ == '__main__':
    address, port = sys.argv[1], int(sys.argv[2])
    ThreadingHTTPServer((address, port), Handler).serve_forever()
