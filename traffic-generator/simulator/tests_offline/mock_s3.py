"""Offline S3 endpoint that VERIFIES AWS Signature Version 4 like SeaweedFS with an s3.json identity (stdlib only).

Read-only: ListObjectsV2, HeadObject, GetObject. Any write is refused. A wrong secret gives 403 SignatureDoesNotMatch,
an unknown key id 403 InvalidAccessKeyId, an unsigned request 403 AccessDenied. Credentials are test values chosen by the
test (never lab credentials).
"""
import hashlib, hmac, re, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

AUTH_RE = re.compile(r"^AWS4-HMAC-SHA256 Credential=([^/]+)/(\d{8})/([^/]+)/s3/aws4_request, ?SignedHeaders=([^,]+), ?Signature=([0-9a-f]{64})$")


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _canon_query(qs):
    pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
    enc = lambda s: urllib.parse.quote(s, safe="-_.~")
    return "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(pairs))


def verify(method, raw_path, headers, secrets):
    """(ok, error_code). headers: lower-cased dict."""
    m = AUTH_RE.match(headers.get("authorization", ""))
    if not m:
        return False, "AccessDenied"
    ak, date, region, signed, sig = m.groups()
    if ak not in secrets:
        return False, "InvalidAccessKeyId"
    path, _, qs = raw_path.partition("?")
    names = signed.split(";")
    canon_headers = "".join(f"{n}:{' '.join(headers.get(n, '').strip().split())}\n" for n in names)
    payload = headers.get("x-amz-content-sha256", hashlib.sha256(b"").hexdigest())
    creq = "\n".join([method, path, _canon_query(qs), canon_headers, signed, payload])
    scope = f"{date}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", headers.get("x-amz-date", ""), scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = _sign(("AWS4" + secrets[ak]).encode(), date); k = _sign(k, region); k = _sign(k, "s3"); k = _sign(k, "aws4_request")
    good = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    return (hmac.compare_digest(good, sig), None if hmac.compare_digest(good, sig) else "SignatureDoesNotMatch")


class MockS3:
    def __init__(self, secrets, objects):
        """secrets: {access_key_id: secret}; objects: {"bucket/key": bytes}."""
        self.secrets, self.objects, self.seen = dict(secrets), dict(objects), []
        mock = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", ctype="application/xml", extra=None, head=False):
                self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if not head:
                    self.wfile.write(body)

            def _err(self, code, err, head=False):
                self._send(code, f"<Error><Code>{err}</Code></Error>".encode(), head=head)

            def _auth(self, head=False):
                h = {k.lower(): v for k, v in self.headers.items()}
                ok, err = verify(self.command, self.path, h, mock.secrets)
                mock.seen.append((self.command, self.path.split("?")[0], ok))
                if not ok:
                    self._err(403, err, head); return False
                return True

            def do_GET(self):
                if not self._auth():
                    return
                path, _, qs = self.path.partition("?")
                parts = urllib.parse.unquote(path).lstrip("/").split("/", 1)
                q = dict(urllib.parse.parse_qsl(qs))
                if len(parts) == 1 or parts[1] == "":
                    if q.get("list-type") != "2":
                        return self._err(400, "InvalidRequest")
                    pre = q.get("prefix", ""); b = parts[0]
                    keys = sorted(k.split("/", 1)[1] for k in mock.objects if k.startswith(b + "/") and k.split("/", 1)[1].startswith(pre))
                    items = "".join(f"<Contents><Key>{escape(k)}</Key><Size>{len(mock.objects[b + '/' + k])}</Size></Contents>" for k in keys)
                    body = (f'<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>{escape(b)}</Name><Prefix>{escape(pre)}</Prefix>'
                            f"<KeyCount>{len(keys)}</KeyCount><IsTruncated>false</IsTruncated>{items}</ListBucketResult>").encode()
                    return self._send(200, body)
                data = mock.objects.get("/".join(parts))
                if data is None:
                    return self._err(404, "NoSuchKey")
                self._send(200, data, "application/octet-stream", {"ETag": '"' + hashlib.md5(data).hexdigest() + '"'})

            def do_HEAD(self):
                if not self._auth(head=True):
                    return
                data = mock.objects.get(urllib.parse.unquote(self.path.split("?")[0]).lstrip("/"))
                if data is None:
                    return self._err(404, "NoSuchKey", head=True)
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.send_header("Content-Type", "application/octet-stream")
                self.end_headers()

            def do_PUT(self):
                mock.seen.append(("PUT", self.path, None)); self._err(403, "AccessDenied")

            def do_DELETE(self):
                mock.seen.append(("DELETE", self.path, None)); self._err(403, "AccessDenied")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H); self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.port = self.httpd.server_address[1]
        self.address = f"127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()
