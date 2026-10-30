"""Minimal stand-in for the privacyIDEA /validate endpoints, used by run.sh.

POST /validate/check
    The OTP 123456 is accepted for every user. The PIN "push" triggers a push
    challenge (transaction PUSH_TRANSACTION), and a check of that transaction
    with an empty password is accepted. Every other value is rejected. The app
    sends multipart/form-data, so the handler parses that as well as url-encoded
    bodies.

GET /validate/polltransaction
    Reports the push as confirmed at once. The answer carries a CORS header,
    because the browser polls from the Nextcloud origin ("Poll in browser").

The log lines include the User-Agent, so run.sh can tell a poll of the browser
from a poll of the Nextcloud server.

    python3 mock_privacyidea.py <bind-address> <port>
"""
import json
import sys
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

VALID_OTP = '123456'
PUSH_PIN = 'push'
PUSH_TRANSACTION = '16786464'
PUSH_MESSAGE = 'Please confirm the authentication on your mobile device!'


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        url = urlparse(self.path)
        if url.path != '/validate/polltransaction':
            self.reply(404, {'result': {'status': False, 'error': {'code': 404, 'message': 'not mocked'}}})
            return
        transaction = parse_qs(url.query).get('transaction_id', [''])[0]
        self.reply(200, {'result': {'status': True, 'value': transaction == PUSH_TRANSACTION}}, cors=True)

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
        password = params.get('pass', '')
        if password == PUSH_PIN:
            self.reply(200, {
                'result': {'status': True, 'value': False, 'authentication': 'CHALLENGE'},
                'detail': {
                    'client_mode': 'poll',
                    'message': PUSH_MESSAGE,
                    'messages': [PUSH_MESSAGE],
                    'multi_challenge': [{
                        'client_mode': 'poll',
                        'message': PUSH_MESSAGE,
                        'serial': 'MOCKPUSH',
                        'transaction_id': PUSH_TRANSACTION,
                        'type': 'push',
                    }],
                    'preferred_client_mode': 'poll',
                    'serial': 'MOCKPUSH',
                    'transaction_id': PUSH_TRANSACTION,
                    'type': 'push',
                },
            })
            return
        accepted = (password == VALID_OTP
                    or (params.get('transaction_id') == PUSH_TRANSACTION and password == ''))
        self.reply(200, {
            'result': {'status': True, 'value': accepted, 'authentication': 'ACCEPT' if accepted else 'REJECT'},
            'detail': {'message': 'matching 1 tokens' if accepted else 'wrong otp value', 'serial': 'MOCK0001'},
        })

    def reply(self, status: int, payload: dict[str, Any], cors: bool = False) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        if cors:
            self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        # A malformed request is logged before its headers are parsed.
        headers = getattr(self, 'headers', None)
        user_agent = headers.get('User-Agent', '') if headers else ''
        sys.stderr.write('%s %s [%s]\n' % (self.address_string(), format % args, user_agent))


if __name__ == '__main__':
    address, port = sys.argv[1], int(sys.argv[2])
    ThreadingHTTPServer((address, port), Handler).serve_forever()
