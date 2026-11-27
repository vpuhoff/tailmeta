"""Чтение трейлера удалённого файла через HTTP Range без загрузки всего файла."""
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from ._core import _read

TAIL_BLOCK = 64 * 1024
CONTENT_RANGE = re.compile(r"bytes (\d+)-(\d+)/(\d+)\Z")
UNSATISFIED_RANGE = re.compile(r"bytes \*/(\d+)\Z")


class RangeReader:
    """Минимальный файловый объект (seek/read) поверх HTTP Range-запросов.

    Первый запрос забирает последние TAIL_BLOCK байт, поэтому небольшие
    метаданные читаются за один запрос.
    """

    def __init__(self, url, timeout=30, user_agent="tailmeta"):
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ValueError("only http:// and https:// URLs are supported")
        self.url, self.timeout, self.user_agent = url, timeout, user_agent
        self.size = None
        self.position = 0
        self.cache_start, self.cache = 0, b""
        self.requests = 0

    def _fetch(self, spec):
        request = urllib.request.Request(self.url, headers={
            "Range": f"bytes={spec}",
            "Accept-Encoding": "identity",
            "User-Agent": self.user_agent,
        })
        self.requests += 1
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            match = UNSATISFIED_RANGE.match(exc.headers.get("Content-Range", "")) if exc.code == 416 else None
            exc.close()
            if match and int(match.group(1)) == 0:
                return 0, b"", 0
            raise
        with response:
            if response.status != 206:
                raise ValueError("server does not support HTTP range requests")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("server applied a content encoding to a range response")
            match = CONTENT_RANGE.match(response.headers.get("Content-Range", ""))
            if not match:
                raise ValueError("invalid Content-Range header")
            start, end, total = map(int, match.groups())
            if end < start or end >= total:
                raise ValueError("invalid Content-Range header")
            data = response.read(end - start + 2)
        if len(data) != end - start + 1:
            raise ValueError("range response length does not match Content-Range")
        if self.size is not None and total != self.size:
            raise ValueError("remote file changed while reading")
        return start, data, total

    def _load_tail(self):
        if self.size is None:
            self.cache_start, self.cache, self.size = self._fetch(f"-{TAIL_BLOCK}")
            if self.cache_start + len(self.cache) != self.size:
                raise ValueError("server returned a range other than the file tail")

    def seek(self, offset, whence=os.SEEK_SET):
        self._load_tail()
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_END:
            position = self.size + offset
        else:
            raise ValueError("unsupported whence")
        if position < 0:
            raise ValueError("negative seek position")
        self.position = position
        return position

    def read(self, size):
        self._load_tail()
        end = min(self.position + size, self.size)
        if end <= self.position:
            return b""
        if not (self.cache_start <= self.position and end <= self.cache_start + len(self.cache)):
            start, data, _ = self._fetch(f"{self.position}-{end - 1}")
            if start != self.position:
                raise ValueError("server returned an unexpected range")
            self.cache_start, self.cache = start, data
        offset = self.position - self.cache_start
        chunk = self.cache[offset:offset + end - self.position]
        self.position += len(chunk)
        return chunk


def read_metadata_url(url, timeout=30):
    """Прочитать недоверенные метаданные удалённого файла через HTTP Range.

    Сервер обязан поддерживать Range (ответ 206); иначе ValueError, без
    загрузки всего файла. Сетевые ошибки поднимаются как OSError.
    """
    from . import __version__
    return _read(RangeReader(url, timeout, f"tailmeta/{__version__}"))[0]
