"""Reading metadata over HTTP Range requests against a local test server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
import unittest
from unittest.mock import patch

from tailmeta import read_metadata_url
from tailmeta import _http
from tailmeta._core import FOOTER, MAGIC, encode_metadata


def trailer(metadata, size=0):
    data = encode_metadata(metadata)
    return b'x' * size + data + FOOTER.pack(len(data), MAGIC)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        server.ranges.append(self.headers.get('Range'))
        body = server.body
        mode = server.mode
        if mode == 'no-range':
            return self._send(200, body)
        match = re.fullmatch(r'bytes=(\d*)-(\d*)', self.headers.get('Range', ''))
        size = len(body)
        if match.group(1):
            start = int(match.group(1))
            end = min(int(match.group(2)), size - 1)
        else:
            start, end = max(size - int(match.group(2)), 0), size - 1
        if size == 0 or start > end:
            return self._send(416, b'', {'Content-Range': f'bytes */{size}'})
        headers = {'Content-Range': f'bytes {start}-{end}/{size}'}
        chunk = body[start:end + 1]
        if mode == 'gzip':
            headers['Content-Encoding'] = 'gzip'
        elif mode == 'bad-range':
            headers['Content-Range'] = 'bytes nonsense'
        elif mode == 'reversed':
            headers['Content-Range'] = f'bytes {end}-{start}/{size}'
        elif mode == 'short':
            headers['Content-Range'] = f'bytes {start}-{end + 5}/{size + 10}'
        elif mode == 'not-tail':
            headers['Content-Range'] = f'bytes 0-{end - start}/{size + 1}'
        elif mode == 'shift' and len(server.ranges) > 1:
            headers['Content-Range'] = f'bytes {start + 1}-{end + 1}/{size}'
        elif mode == 'grow' and len(server.ranges) > 1:
            headers['Content-Range'] = f'bytes {start}-{end}/{size + 1}'
        self._send(206, chunk, headers)

    def _send(self, status, body, headers=()):
        self.send_response(status)
        for key, value in dict(headers).items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.server.server_address[1]}/app.bin'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def serve(self, body, mode='ok'):
        self.server.body, self.server.mode, self.server.ranges = body, mode, []

    def test_small_trailer_uses_one_request(self):
        self.serve(trailer({'version': '1.2.4'}, size=10 * 1024 * 1024))
        self.assertEqual(read_metadata_url(self.url), {'version': '1.2.4'})
        self.assertEqual(self.server.ranges, [f'bytes=-{_http.TAIL_BLOCK}'])

    def test_large_trailer_fetches_the_rest(self):
        metadata = {'version': '2', 'notes': 'n' * (_http.TAIL_BLOCK * 2)}
        self.serve(trailer(metadata, size=1000))
        self.assertEqual(read_metadata_url(self.url), metadata)
        self.assertEqual(len(self.server.ranges), 2)

    def test_small_and_empty_files(self):
        for body in (b'', b'abc', trailer({'version': '3'})):
            self.serve(body)
            expected = {'version': '3'} if len(body) > 3 else None
            self.assertEqual(read_metadata_url(self.url), expected)

    def test_server_errors(self):
        for mode, message in (
            ('no-range', 'does not support HTTP range'),
            ('gzip', 'content encoding'),
            ('bad-range', 'invalid Content-Range'),
            ('reversed', 'invalid Content-Range'),
            ('short', 'length does not match'),
            ('not-tail', 'other than the file tail'),
        ):
            self.serve(trailer({'version': '1'}, size=10), mode)
            with self.assertRaisesRegex(ValueError, message):
                read_metadata_url(self.url)
        for mode, message in (('shift', 'unexpected range'), ('grow', 'remote file changed')):
            self.serve(trailer({'version': '1', 'notes': 'n' * _http.TAIL_BLOCK}), mode)
            with self.assertRaisesRegex(ValueError, message):
                read_metadata_url(self.url)

    def test_http_errors_are_os_errors(self):
        self.serve(b'')
        with patch.object(Handler, 'do_GET', lambda self: self._send(404, b'')):
            with self.assertRaises(OSError):
                read_metadata_url(self.url)

    def test_only_http_urls(self):
        for url in ('file:///etc/passwd', 'ftp://example.com/x', '/local/path'):
            with self.assertRaisesRegex(ValueError, 'only http'):
                read_metadata_url(url)

    def test_reader_seek_and_read_edges(self):
        self.serve(b'0123456789')
        reader = _http.RangeReader(self.url)
        self.assertEqual(reader.seek(0, 2), 10)
        self.assertEqual(reader.read(4), b'')
        reader.seek(8)
        self.assertEqual(reader.read(100), b'89')
        with self.assertRaisesRegex(ValueError, 'whence'):
            reader.seek(0, 1)
        with self.assertRaisesRegex(ValueError, 'negative'):
            reader.seek(-11, 2)


if __name__ == '__main__':
    unittest.main()
