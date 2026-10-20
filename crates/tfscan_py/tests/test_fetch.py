"""Deterministic registry/download fixtures; no public services."""
import contextlib
import http.server
import io
import json
import tarfile
import threading
import zipfile

import pytest
import tfscan


@contextlib.contextmanager
def server(routes):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            status, headers, body = routes(self.path)
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=httpd.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", requests
    finally:
        httpd.shutdown()
        worker.join()
        httpd.server_close()


def registry(download):
    def routes(path):
        if path == "/.well-known/terraform.json":
            return 200, {}, b'{"modules.v1":"/modules/"}'
        if path == "/modules/acme/example/aws/versions":
            return 200, {}, b'{"modules":[{"versions":[{"version":"1.0.0"}]}]}'
        if path == "/modules/acme/example/aws/1.0.0/download":
            return 204, {"X-Terraform-Get": download}, b""
        return 404, {}, b""
    return routes


def root(tmp_path):
    (tmp_path / "main.tf").write_text('module "r" { source = "registry.fixture/acme/example/aws" }\n')


def tar_package(name="main.tf", kind=tarfile.REGTYPE, size=None):
    body = b'resource "test_node" "n" {}\n'
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(body) if size is None else size
    if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        info.linkname = "../outside"
        info.size = 0
    # Permit intentionally oversized/truncated entries without allocating them.
    return info.tobuf() + body + b"\0" * (512 - len(body)) + b"\0" * 1024


def test_private_registry_token_stays_on_its_origin_and_out_of_cache(tmp_path, monkeypatch):
    root(tmp_path)
    monkeypatch.setenv("TF_TOKEN_registry_fixture", "private-registry-token")
    with server(lambda _: (200, {}, tar_package())) as (archive_url, archive_requests):
        with server(registry(archive_url + "/download?signature=private-download-token")) as (registry_url, registry_requests):
            report = tfscan.fetch(tmp_path, registry_origins={"registry.fixture": registry_url})
    assert registry_requests and all(token == "Bearer private-registry-token" for _, token in registry_requests)
    assert archive_requests and all(token is None for _, token in archive_requests)
    assert report["modules"][0]["version"] == "1.0.0"
    metadata = (tmp_path / ".terraform/modules/modules.json").read_text() + json.dumps(report)
    assert "private-registry-token" not in metadata
    assert "private-download-token" not in metadata
    assert tfscan.scan(tmp_path, builtin=False, bundled=False).status == "complete"
    assert tfscan.fetch(tmp_path)["modules"][0]["reused"]


@pytest.mark.parametrize("package", [
    tar_package("../escape.tf"),
    tar_package("/absolute.tf"),
    tar_package("link", tarfile.SYMTYPE),
    tar_package("link", tarfile.LNKTYPE),
    tar_package("device", tarfile.CHRTYPE),
    tar_package("large.tf", size=129 * 1024 * 1024),
])
def test_unsafe_or_oversized_packages_never_publish_a_manifest(tmp_path, package):
    root(tmp_path)
    with server(lambda _: (200, {}, package)) as (archive_url, _):
        with server(registry(archive_url + "/package.tar")) as (registry_url, _):
            with pytest.raises(ValueError):
                tfscan.fetch(tmp_path, registry_origins={"registry.fixture": registry_url})
    assert not (tmp_path / ".terraform/modules/modules.json").exists()
    assert not (tmp_path.parent / "escape.tf").exists()


def test_zip_module_package_and_failure_redaction(tmp_path):
    root(tmp_path)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr("main.tf", 'resource "test_node" "n" {}\n')
    with server(lambda _: (200, {}, archive.getvalue())) as (archive_url, _):
        with server(registry(archive_url + "/package.zip")) as (registry_url, _):
            tfscan.fetch(tmp_path, registry_origins={"registry.fixture": registry_url})
    assert tfscan.scan(tmp_path, builtin=False, bundled=False).status == "complete"
    previous = (tmp_path / ".terraform/modules/modules.json").read_bytes()
    with server(lambda _: (403, {}, b"private-token")) as (archive_url, _):
        with server(registry(archive_url + "/private-token")) as (registry_url, _):
            with pytest.raises(ValueError) as error:
                tfscan.fetch(tmp_path, refresh=True, registry_origins={"registry.fixture": registry_url})
    assert "private-token" not in str(error.value)
    assert previous == (tmp_path / ".terraform/modules/modules.json").read_bytes()
