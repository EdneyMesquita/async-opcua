//! Tests for `MessageTap`, the plaintext chunk observer of the secure channel.

use std::{
    io::Cursor,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use opcua::{
    client::{IdentityToken, Session},
    core::{
        comms::{
            message_chunk::{MessageChunkType, MessageIsFinalType},
            tap::{MessageTap, TapDirection, TappedChunk},
        },
        Message, RequestMessage, ResponseMessage,
    },
    crypto::SecurityPolicy,
    types::{
        AttributeId, BinaryDecodable, BinaryEncodable, ContextOwned, DecodingOptions,
        MessageSecurityMode, NamespaceMap, NodeId, TimestampsToReturn, VariableId,
    },
};

use crate::utils::{hostname, read_value_id, test_server, Tester};

/// An owned copy of a [`TappedChunk`].
#[derive(Debug, Clone)]
struct Recorded {
    direction: TapDirection,
    message_type: MessageChunkType,
    is_final: MessageIsFinalType,
    secure_channel_id: u32,
    token_id: Option<u32>,
    sequence_number: u32,
    request_id: u32,
    bytes: Vec<u8>,
    body: std::ops::Range<usize>,
}

impl Recorded {
    fn body(&self) -> &[u8] {
        &self.bytes[self.body.clone()]
    }
}

#[derive(Default)]
struct Recorder(Mutex<Vec<Recorded>>);

impl Recorder {
    fn chunks(&self) -> Vec<Recorded> {
        self.0.lock().unwrap().clone()
    }
}

impl MessageTap for Recorder {
    fn on_chunk(&self, chunk: &TappedChunk<'_>) {
        self.0.lock().unwrap().push(Recorded {
            direction: chunk.direction,
            message_type: chunk.message_type,
            is_final: chunk.is_final,
            secure_channel_id: chunk.secure_channel_id,
            token_id: chunk.token_id,
            sequence_number: chunk.sequence_number,
            request_id: chunk.request_id,
            bytes: chunk.bytes.to_vec(),
            body: chunk.body.clone(),
        });
    }
}

/// Decode the body of a single-chunk message, and encode it again.
/// Returns the decoded message and the re-encoded body.
fn decode_and_reencode<T: Message>(body: &[u8]) -> (T, Vec<u8>) {
    let ctx_owned = ContextOwned::new_default(NamespaceMap::new(), DecodingOptions::default());
    let ctx = ctx_owned.context();
    let mut stream = Cursor::new(body);
    let node_id = NodeId::decode(&mut stream, &ctx).expect("body starts with a TypeId");
    let object_id = node_id.as_object_id().expect("TypeId is an object id");
    let message = T::decode_by_object_id(&mut stream, object_id, &ctx).expect("body decodes");
    assert_eq!(
        stream.position() as usize,
        body.len(),
        "the whole body is the message"
    );

    let mut encoded = Vec::new();
    message.type_id().encode(&mut encoded, &ctx).unwrap();
    message.encode(&mut encoded, &ctx).unwrap();
    (message, encoded)
}

async fn connect_with_tap(
    tester: &mut Tester,
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
    tap: Arc<dyn MessageTap>,
) -> (
    Arc<Session>,
    tokio::task::JoinHandle<opcua::types::StatusCode>,
) {
    let url = tester.endpoint();
    let endpoints = tester
        .client
        .get_server_endpoints_from_url(url.as_str())
        .await
        .unwrap();
    let (session, event_loop) = tester
        .client
        .session_builder()
        .with_endpoints(endpoints)
        .connect_to_matching_endpoint((url.as_str(), policy.to_str(), mode))
        .unwrap()
        .user_identity_token(IdentityToken::Anonymous)
        .message_tap(tap)
        .build(tester.client.certificate_store().clone())
        .unwrap();
    let handle = event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();
    (session, handle)
}

/// Connect, do a Read, disconnect, and return everything the tap saw.
async fn record_read(policy: SecurityPolicy, mode: MessageSecurityMode) -> Vec<Recorded> {
    let mut tester = Tester::new(test_server(), false).await;
    let recorder = Arc::new(Recorder::default());
    let (session, event_loop) = connect_with_tap(&mut tester, policy, mode, recorder.clone()).await;

    let values = session
        .read(
            &[read_value_id(
                AttributeId::Value,
                VariableId::Server_ServiceLevel,
            )],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    assert_eq!(1, values.len());

    session.disconnect().await.unwrap();
    // Wait for the transport to be done, so that the CloseSecureChannel chunk has been sent.
    tokio::time::timeout(Duration::from_secs(5), event_loop)
        .await
        .unwrap()
        .unwrap();

    recorder.chunks()
}

fn in_direction(chunks: &[Recorded], direction: TapDirection) -> Vec<&Recorded> {
    chunks.iter().filter(|c| c.direction == direction).collect()
}

/// The checks that hold for any security policy and mode.
fn check_chunks(chunks: &[Recorded]) {
    let sent = in_direction(chunks, TapDirection::Send);
    let received = in_direction(chunks, TapDirection::Receive);
    assert!(!sent.is_empty(), "no chunks sent");
    assert!(!received.is_empty(), "no chunks received");

    // Sequence numbers increase by one per chunk in each direction, across OPN and MSG.
    for (name, list) in [("sent", &sent), ("received", &received)] {
        for pair in list.windows(2) {
            assert!(
                pair[1].sequence_number > pair[0].sequence_number,
                "{name} sequence numbers must be strictly increasing: {} then {}",
                pair[0].sequence_number,
                pair[1].sequence_number
            );
            assert_eq!(
                pair[1].sequence_number,
                pair[0].sequence_number + 1,
                "{name} sequence numbers must increase by one"
            );
        }
    }

    // The plaintext chunk is consistent with its metadata.
    for c in chunks {
        let header_size = 12;
        assert_eq!(
            &c.bytes[..3],
            match c.message_type {
                MessageChunkType::Message => b"MSG",
                MessageChunkType::OpenSecureChannel => b"OPN",
                MessageChunkType::CloseSecureChannel => b"CLO",
            }
        );
        assert_eq!(
            u32::from_le_bytes(c.bytes[4..8].try_into().unwrap()) as usize,
            c.bytes.len(),
            "the message size is the size of the plaintext chunk"
        );
        assert_eq!(
            u32::from_le_bytes(c.bytes[8..12].try_into().unwrap()),
            c.secure_channel_id
        );
        assert!(c.body.end == c.bytes.len() && c.body.start > header_size + 8);
        // The sequence header is directly before the body.
        let seq = &c.bytes[c.body.start - 8..c.body.start];
        assert_eq!(
            u32::from_le_bytes(seq[..4].try_into().unwrap()),
            c.sequence_number
        );
        assert_eq!(
            u32::from_le_bytes(seq[4..].try_into().unwrap()),
            c.request_id
        );
        match c.message_type {
            MessageChunkType::OpenSecureChannel => assert_eq!(c.token_id, None),
            _ => {
                // Symmetric security header: the token id sits right after the message header.
                let token = u32::from_le_bytes(c.bytes[12..16].try_into().unwrap());
                assert_eq!(c.token_id, Some(token));
                assert_eq!(c.body.start, 16 + 8);
            }
        }
    }

    // The channel starts with an OpenSecureChannel request and response, and ends with
    // a CloseSecureChannel request, which has no response.
    let opn_sent = sent
        .iter()
        .find(|c| c.message_type == MessageChunkType::OpenSecureChannel)
        .expect("OpenSecureChannel request");
    let opn_received = received
        .iter()
        .find(|c| c.message_type == MessageChunkType::OpenSecureChannel)
        .expect("OpenSecureChannel response");
    assert_eq!(opn_sent.request_id, opn_received.request_id);
    assert_eq!(
        opn_sent.secure_channel_id, 0,
        "no channel id before the OPN response"
    );
    assert_ne!(opn_received.secure_channel_id, 0);
    assert_eq!(sent[0].message_type, MessageChunkType::OpenSecureChannel);
    assert_eq!(
        sent.last().unwrap().message_type,
        MessageChunkType::CloseSecureChannel
    );
    assert!(received
        .iter()
        .all(|c| c.message_type != MessageChunkType::CloseSecureChannel));

    // OPN and MSG bodies decode, and re-encode to exactly the same bytes.
    let mut requests = Vec::new();
    let mut responses = Vec::new();
    for c in chunks {
        assert_eq!(
            c.is_final,
            MessageIsFinalType::Final,
            "all messages fit in a chunk"
        );
        match c.direction {
            TapDirection::Send => {
                let (message, encoded) = decode_and_reencode::<RequestMessage>(c.body());
                assert_eq!(
                    encoded,
                    c.body(),
                    "re-encoded request {}",
                    message.type_name()
                );
                requests.push((c, message));
            }
            TapDirection::Receive => {
                let (message, encoded) = decode_and_reencode::<ResponseMessage>(c.body());
                assert_eq!(
                    encoded,
                    c.body(),
                    "re-encoded response {}",
                    message.type_name()
                );
                responses.push((c, message));
            }
        }
    }

    // Every response has the request id and request handle of a request, of the matching type.
    for (response_chunk, response) in &responses {
        let (request_chunk, request) = requests
            .iter()
            .find(|(c, _)| c.request_id == response_chunk.request_id)
            .unwrap_or_else(|| panic!("no request for response {}", response.type_name()));
        assert_eq!(
            request.request_header().request_handle,
            response.response_header().request_handle,
            "{} {}",
            request.type_name(),
            response.type_name()
        );
        // The server answers with a ServiceFault when it cannot process a request, which
        // happens to requests that are still in flight when the session is closed.
        if !matches!(response, ResponseMessage::ServiceFault(_)) {
            assert_eq!(
                request.type_name().trim_end_matches("Request"),
                response.type_name().trim_end_matches("Response"),
            );
        }
        if request_chunk.message_type == MessageChunkType::Message {
            assert_eq!(
                request_chunk.secure_channel_id,
                response_chunk.secure_channel_id
            );
        }
        assert_eq!(request_chunk.message_type, response_chunk.message_type);
    }
    // The Read we made is there, and it was answered. Other requests may be in flight when the
    // session is closed, so we only check this one.
    let service_level: NodeId = VariableId::Server_ServiceLevel.into();
    let (read_chunk, read_request) = requests
        .iter()
        .find(|(_, m)| match m {
            RequestMessage::Read(r) => r
                .nodes_to_read
                .as_ref()
                .is_some_and(|n| n.iter().any(|n| n.node_id == service_level)),
            _ => false,
        })
        .expect("our Read request");
    let (_, response) = responses
        .iter()
        .find(|(c, _)| c.request_id == read_chunk.request_id)
        .expect("response to our Read");
    assert!(matches!(response, ResponseMessage::Read(_)));
    assert_eq!(
        read_request.request_header().request_handle,
        response.response_header().request_handle
    );
}

#[tokio::test]
async fn message_tap_security_none() {
    let chunks = record_read(SecurityPolicy::None, MessageSecurityMode::None).await;
    check_chunks(&chunks);
}

#[tokio::test]
async fn message_tap_basic256sha256_sign_and_encrypt() {
    let chunks = record_read(
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
    check_chunks(&chunks);
}

#[tokio::test]
async fn message_tap_basic256sha256_sign() {
    let chunks = record_read(SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign).await;
    check_chunks(&chunks);
}

/// A TCP proxy between the client and the server that records every byte the client sends.
/// Returns the address the client should connect to, and the recorded bytes.
async fn recording_proxy(
    server: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<u8>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind(format!("{}:0", hostname()))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let wire: Arc<Mutex<Vec<u8>>> = Arc::default();
    let client_to_server = wire.clone();
    let done = tokio::spawn(async move {
        let Ok((client, _)) = listener.accept().await else {
            return;
        };
        let Ok(upstream) = TcpStream::connect(server).await else {
            return;
        };
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = upstream.into_split();
        let up = async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = client_read.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                client_to_server
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buf[..n]);
                if server_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        let down = async move {
            let mut buf = vec![0u8; 16 * 1024];
            while let Ok(n) = server_read.read(&mut buf).await {
                if n == 0 || client_write.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        tokio::join!(up, down);
    });
    (addr, wire, done)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Connect through the recording proxy, and return what the tap saw and what was on the wire.
async fn record_read_with_wire(
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
) -> (Vec<Recorded>, Vec<u8>) {
    let tester = Tester::new(test_server(), false).await;
    let (proxy_addr, wire, proxy_done) = recording_proxy(tester.addr).await;
    let proxy_url = format!("opc.tcp://{}:{}/", hostname(), proxy_addr.port());

    let mut endpoint = tester
        .client
        .get_server_endpoints_from_url(tester.endpoint().as_str())
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.security_policy_uri.as_ref() == policy.to_uri() && e.security_mode == mode)
        .unwrap();
    endpoint.endpoint_url = proxy_url.as_str().into();

    let recorder = Arc::new(Recorder::default());
    let (session, event_loop) = tester
        .client
        .session_builder()
        .connect_to_endpoint_directly(endpoint)
        .unwrap()
        .user_identity_token(IdentityToken::Anonymous)
        .message_tap(recorder.clone())
        .build(tester.client.certificate_store().clone())
        .unwrap();
    let event_loop = event_loop.spawn();
    tokio::time::timeout(Duration::from_secs(20), session.wait_for_connection())
        .await
        .unwrap();
    session
        .read(
            &[read_value_id(
                AttributeId::Value,
                VariableId::Server_ServiceLevel,
            )],
            TimestampsToReturn::Both,
            0.0,
        )
        .await
        .unwrap();
    session.disconnect().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), event_loop)
        .await
        .unwrap()
        .unwrap();

    // Wait until the proxy has seen the connection close, so it has recorded everything.
    tokio::time::timeout(Duration::from_secs(5), proxy_done)
        .await
        .unwrap()
        .unwrap();
    let wire = wire.lock().unwrap().clone();
    (recorder.chunks(), wire)
}

/// Whether the plaintext of the chunks the client sent can be found in what the client put on
/// the wire. The first 32 bytes of the message body cover the TypeId and the request header,
/// which is a timestamp, so it cannot be a coincidence.
fn plaintext_on_wire(chunks: &[Recorded], wire: &[u8]) -> Vec<bool> {
    chunks
        .iter()
        .filter(|c| c.direction == TapDirection::Send)
        .map(|c| contains(wire, &c.body()[..32.min(c.body().len())]))
        .collect()
}

#[tokio::test]
async fn message_tap_is_plaintext_on_encrypted_channel() {
    // With no security, what the tap gets is what is on the wire. This also checks the proxy.
    let (chunks, wire) =
        record_read_with_wire(SecurityPolicy::None, MessageSecurityMode::None).await;
    check_chunks(&chunks);
    assert!(
        plaintext_on_wire(&chunks, &wire).iter().all(|p| *p),
        "unsecured chunks are on the wire as the tap saw them: {:?}",
        plaintext_on_wire(&chunks, &wire)
    );

    // With SignAndEncrypt, the tap still gets plaintext that decodes (see check_chunks), but it
    // is not on the wire.
    let (chunks, wire) = record_read_with_wire(
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
    check_chunks(&chunks);
    let on_wire = plaintext_on_wire(&chunks, &wire);
    assert!(!on_wire.is_empty());
    assert!(
        on_wire.iter().all(|p| !*p),
        "encrypted chunks must not contain their plaintext on the wire: {on_wire:?}"
    );
    // The message header, which is not encrypted, is.
    assert!(contains(&wire, b"OPN"));
    assert!(contains(&wire, b"MSG"));
}
