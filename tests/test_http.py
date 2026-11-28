"""Reading metadata over HTTP Range requests against a local test server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import threading
import unittest
from unittest.mock import patch

from tailmeta import read_metadata_url
from tailmeta import _http
from tailmeta._core import encode_footer, encode_metadata


def trailer(metadata, size=0, format_version=3):
    data = encode_metadata(metadata)
    return b'x' * size + data + encode_footer(data, format_version)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        server = self.server
        server.ranges.append(self.headers.get('Range'))
        server.if_range.append(self.headers.get('If-Range'))
        body = server.body
        mode = server.mode
        if mode == 'no-range':
            return self._send(200, body)
        second = len(server.ranges) > 1
        validators = {}
        if mode in ('etag', 'etag-change', 'etag-change-ignored', 'etag-vanish'):
            validators['ETag'] = '"v2"' if second and mode != 'etag' else '"v1"'
            if mode == 'etag-vanish' and second:
                del validators['ETag']
        elif mode == 'weak-etag':
            validators['ETag'] = 'W/"v2"' if second else 'W/"v1"'
        elif mode == 'last-modified':
            validators['Last-Modified'] = 'Thu, 02 Jan 2025 00:00:00 GMT' if second else 'Wed, 01 Jan 2025 00:00:00 GMT'
        if_range = self.headers.get('If-Range')
        if if_range and mode != 'etag-change-ignored' and if_range != validators.get('ETag'):
            # RFC 9110: a failed If-Range returns the whole current representation.
            return self._send(200, body, validators)
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
        self._send(206, chunk, {**headers, **validators})

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
        self.server.body, self.server.mode, self.server.ranges, self.server.if_range = body, mode, [], []

    def test_small_trailer_uses_one_request(self):
        self.serve(trailer({'version': '1.2.4'}, size=10 * 1024 * 1024))
        self.assertEqual(read_metadata_url(self.url), {'version': '1.2.4'})
        self.assertEqual(self.server.ranges, [f'bytes=-{_http.TAIL_BLOCK}'])

    def test_large_trailer_fetches_the_rest(self):
        metadata = {'version': '2', 'notes': 'n' * (_http.TAIL_BLOCK * 2)}
        self.serve(trailer(metadata, size=1000))
        self.assertEqual(read_metadata_url(self.url), metadata)
        self.assertEqual(len(self.server.ranges), 2)

    def test_v2_trailer(self):
        self.serve(trailer({'version': '2.0'}, size=100, format_version=2))
        self.assertEqual(read_metadata_url(self.url), {'version': '2.0'})

    def test_matching_etag_is_sent_in_if_range(self):
        metadata = {'version': '2', 'notes': 'n' * (_http.TAIL_BLOCK * 2)}
        self.serve(trailer(metadata, size=1000), 'etag')
        self.assertEqual(read_metadata_url(self.url), metadata)
        self.assertEqual(self.server.if_range, [None, '"v1"'])

    def test_file_replaced_between_requests(self):
        metadata = {'version': '1', 'notes': 'n' * _http.TAIL_BLOCK}
        for mode in ('etag-change', 'etag-change-ignored', 'etag-vanish', 'weak-etag', 'last-modified'):
            self.serve(trailer(metadata), mode)
            with self.assertRaisesRegex(ValueError, 'remote file changed', msg=mode):
                read_metadata_url(self.url)
            self.assertEqual(len(self.server.ranges), 2, mode)
            if mode == 'weak-etag':
                self.assertEqual(self.server.if_range, [None, None], 'weak ETags are not sent in If-Range')

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
