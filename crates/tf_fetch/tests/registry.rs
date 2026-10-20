use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};
use tf_fetch::{FetchRequest, fetch};

fn package() -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    let source = b"resource \"test_node\" \"n\" { value = 1 }\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(source.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "modules/child/main.tf", &source[..])
        .unwrap();
    tar.into_inner().unwrap()
}

#[test]
fn registry_selects_versions_and_reuses_the_cache_without_a_server() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let server = thread::spawn(move || {
        let archive = package();
        while !flag.load(Ordering::Relaxed) {
            let Ok((mut stream, _)) = listener.accept() else {
                thread::sleep(std::time::Duration::from_millis(5));
                continue;
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            let mut bytes = [0; 8192];
            let len = stream.read(&mut bytes).unwrap();
            let req = String::from_utf8_lossy(&bytes[..len]);
            let path = req.split_whitespace().nth(1).unwrap();
            let (status, extra, body) = match path {
                "/.well-known/terraform.json" => (200, "", br#"{"modules.v1":"/v1/modules/"}"#.as_slice()),
                "/v1/modules/acme/test/aws/versions" => (200, "", br#"{"modules":[{"versions":[{"version":"1.0.0"},{"version":"1.2.0"},{"version":"2.0.0"}]}]}"#.as_slice()),
                "/v1/modules/acme/test/aws/1.2.0/download" => (204, "X-Terraform-Get: /package.tar\r\n", b"".as_slice()),
                "/package.tar" => (200, "", archive.as_slice()),
                _ => (404, "", b"".as_slice()),
            };
            write!(
                stream,
                "HTTP/1.1 {status} OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(body).unwrap();
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    fs::write(tmp.path().join("main.tf.json"), r#"{"module":{"r":{"source":"registry.example/acme/test/aws//modules/child","version":"~> 1.0"}}}"#).unwrap();
    let mut request = FetchRequest::new(tmp.path());
    request
        .registry_origins
        .insert("registry.example".into(), format!("http://{addr}"));
    let result = fetch(request.clone());
    done.store(true, Ordering::Relaxed);
    server.join().unwrap();
    let first = result.unwrap();
    assert_eq!(first.modules[0].version.as_deref(), Some("1.2.0"));
    assert!(
        first.modules[0]
            .revision
            .as_ref()
            .unwrap()
            .starts_with("sha256:")
    );
    let second = fetch(request).unwrap();
    assert!(second.modules[0].reused);
    assert_eq!(second.modules[0].revision, first.modules[0].revision);
}
