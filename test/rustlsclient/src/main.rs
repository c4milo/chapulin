// A rustls TLS 1.3 client for test/e2e.sh's runs against this tree's
// server. It makes two connections with one ClientConfig, so the second
// presents the ticket the first received. Each one sends a line, reads
// the server's one-line reply and prints "full <reply>" or
// "resumed <reply>".
//
// The server's certificate is self-signed with CA:TRUE, which webpki
// refuses as an end entity. So the client takes exactly the certificate
// DER it was given, and checks CertificateVerify with rustls's own
// verifier. Every other check is rustls's, among them the refusal of an
// extension response the hello did not ask for (RFC 9846 §4.3).
//
// Usage: rustlsclient HOST:PORT CERT.der LINE
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, Error, HandshakeKind,
             SignatureScheme, StreamOwned};

#[derive(Debug)]
struct Pinned {
    cert: Vec<u8>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>,
                          intermediates: &[CertificateDer<'_>], _server_name: &ServerName<'_>,
                          _ocsp_response: &[u8], _now: UnixTime)
                          -> Result<ServerCertVerified, Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.cert.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("not the pinned certificate".into()))
        }
    }

    fn verify_tls12_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
                              dss: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss,
                               &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(&self, message: &[u8], cert: &CertificateDer<'_>,
                              dss: &DigitallySignedStruct)
                              -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss,
                               &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// One connection: the line out, the reply back, and how the handshake ran.
fn exchange(config: &Arc<ClientConfig>, addr: &str, line: &str) -> Result<String, String> {
    let name = ServerName::try_from("sapo").map_err(|e| e.to_string())?;
    let conn = ClientConnection::new(config.clone(), name).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(addr).map_err(|e| e.to_string())?;
    let mut tls = StreamOwned::new(conn, tcp);
    tls.write_all(format!("{line}\n").as_bytes()).map_err(|e| e.to_string())?;
    let mut reply = String::new();
    BufReader::new(&mut tls).read_line(&mut reply).map_err(|e| e.to_string())?;
    let kind = match tls.conn.handshake_kind() {
        Some(HandshakeKind::Resumed) => "resumed",
        Some(_) => "full",
        None => return Err("no handshake".into()),
    };
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(format!("{kind} {}", reply.trim_end()))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: rustlsclient HOST:PORT CERT.der LINE");
        std::process::exit(2);
    }
    let cert = std::fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("rustlsclient: {}: {e}", args[2]);
        std::process::exit(2);
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Pinned { cert, provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 with the ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let config = Arc::new(config);
    for _ in 0..2 {
        match exchange(&config, &args[1], &args[3]) {
            Ok(out) => println!("{out}"),
            Err(e) => {
                eprintln!("rustlsclient: {e}");
                std::process::exit(1);
            }
        }
    }
}
