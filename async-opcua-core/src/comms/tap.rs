//! A passive observer for the secure channel layer, [`MessageTap`].
//!
//! A tap sees every message chunk that is sent or received on a secure channel
//! _after_ it has been decrypted and verified (receive) or _before_ it is signed and encrypted
//! (send). This makes it possible to build wire-level tools, such as protocol analyzers or
//! service call tracers, that work on encrypted channels, without copying any transport code
//! or having to re-derive sequence numbers.
//!
//! The tap is purely an observer. It cannot modify, drop or delay chunks, and when no tap is
//! installed the only cost is an `Option` check per chunk.

use std::ops::Range;

use super::{
    message_chunk::{MessageChunk, MessageChunkType, MessageIsFinalType},
    message_chunk_info::ChunkInfo,
    security_header::SecurityHeader,
};

/// Direction of a [`TappedChunk`], from the point of view of the stack that owns the tap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TapDirection {
    /// The chunk is being sent to the peer.
    Send,
    /// The chunk has been received from the peer.
    Receive,
}

/// A single plaintext message chunk, as seen by a [`MessageTap`].
///
/// # Contents of `bytes`
///
/// `bytes` is the chunk exactly as it looks with security removed, in both directions:
///
/// ```text
/// message header (12 bytes) | security header | sequence header (8 bytes) | body
/// ```
///
///  - The message header is `MSG`/`OPN`/`CLO`, the chunk type `C`/`F`/`A`, the message size
///    and the secure channel id. The message size is the size of `bytes`, not of the chunk on
///    the wire: it does not include padding, signature or any encryption overhead.
///  - The security header is asymmetric for `OPN` chunks (security policy URI, sender
///    certificate, receiver certificate thumbprint) and symmetric (the token id) otherwise.
///  - The sequence header is the sequence number and request id.
///  - The body is the payload, which for the first chunk of a message starts with the encoded
///    `TypeId` of the service request or response. A message may span several chunks, in
///    which case the body of each chunk is a slice of the message.
///
/// The padding and signature are **not** included. When sending, they have not been added yet.
/// When receiving, they have been verified and removed. The chunk is therefore the same
/// whether the channel uses `SecurityPolicy::None`, `Sign` or `SignAndEncrypt`.
#[derive(Debug, Clone)]
pub struct TappedChunk<'a> {
    /// Whether the chunk was sent or received.
    pub direction: TapDirection,
    /// Kind of chunk: a service message, `OpenSecureChannel` or `CloseSecureChannel`.
    pub message_type: MessageChunkType,
    /// Whether this is an intermediate chunk, the final chunk of a message, or an abort.
    pub is_final: MessageIsFinalType,
    /// Secure channel id from the message header. This is 0 on the first `OpenSecureChannel`
    /// request, before the server has assigned an id.
    pub secure_channel_id: u32,
    /// Security token id from the symmetric security header, `None` for `OpenSecureChannel`
    /// chunks, which have an asymmetric security header and no token.
    pub token_id: Option<u32>,
    /// Sequence number from the sequence header. This is the number actually sent on or
    /// received from the wire.
    pub sequence_number: u32,
    /// Request id from the sequence header. Chunks of the same message share it, and a
    /// response has the request id of the request it answers.
    pub request_id: u32,
    /// The whole plaintext chunk, see the type documentation for what it contains.
    pub bytes: &'a [u8],
    /// The range of `bytes` that is the message body: the payload without message header,
    /// security header, sequence header, padding or signature.
    pub body: Range<usize>,
}

impl<'a> TappedChunk<'a> {
    /// Create a tapped chunk from a plaintext chunk and its decoded [`ChunkInfo`].
    ///
    /// `chunk` must have had security removed, or not have had it applied yet, which is the
    /// state in which [`ChunkInfo`] is valid.
    pub fn new(direction: TapDirection, chunk: &'a MessageChunk, info: &ChunkInfo) -> Self {
        let token_id = match &info.security_header {
            SecurityHeader::Symmetric(h) => Some(h.token_id),
            SecurityHeader::Asymmetric(_) => None,
        };
        Self {
            direction,
            message_type: info.message_header.message_type,
            is_final: info.message_header.is_final,
            secure_channel_id: info.message_header.secure_channel_id,
            token_id,
            sequence_number: info.sequence_header.sequence_number,
            request_id: info.sequence_header.request_id,
            bytes: &chunk.data,
            body: info.body_offset..chunk.data.len(),
        }
    }

    /// The message body, `&self.bytes[self.body]`.
    pub fn body_bytes(&self) -> &'a [u8] {
        &self.bytes[self.body.clone()]
    }
}

/// Observer of the plaintext message chunks of a secure channel.
///
/// Install one on a client with `SessionBuilder::message_tap` to see every chunk the
/// client sends and receives, in wire order, including the `OpenSecureChannel` and
/// `CloseSecureChannel` chunks, and including chunks on channels that are signed or
/// encrypted. See [`TappedChunk`] for exactly what is delivered.
///
/// # Requirements
///
/// [`MessageTap::on_chunk`] is called synchronously on the transport task, between
/// two steps of the transport's event loop. It must therefore
///
///  - return quickly and never block. Do not take a contended lock or do I/O. Copy what you need
///    and hand it to another task, for example through an unbounded channel, if more work is
///    required.
///  - not panic, which would take down the transport.
///  - not call back into the session in a way that waits for a response, since that
///    response can only be processed by the same task.
///
/// Chunks are delivered in the order they are sent or received, per direction. A client
/// that reconnects starts a new secure channel with new sequence numbers, and the same tap
/// continues to receive chunks.
///
/// # Example
///
/// Record `(direction, sequence number, request id, body)` for every chunk. Any
/// `Fn(&TappedChunk<'_>) + Send + Sync + 'static` closure is a tap, so this works without
/// a named type:
///
/// ```
/// use std::sync::{Arc, Mutex};
/// use opcua_core::comms::tap::{MessageTap, TapDirection, TappedChunk};
///
/// let log: Arc<Mutex<Vec<(TapDirection, u32, u32, Vec<u8>)>>> = Arc::default();
/// let sink = log.clone();
/// let tap: Arc<dyn MessageTap> = Arc::new(move |chunk: &TappedChunk<'_>| {
///     sink.lock().unwrap().push((
///         chunk.direction,
///         chunk.sequence_number,
///         chunk.request_id,
///         chunk.body_bytes().to_vec(),
///     ));
/// });
/// // `tap` can now be passed to `SessionBuilder::message_tap`.
/// # let _ = tap;
/// ```
///
/// Or with a named type:
///
/// ```
/// use std::sync::atomic::{AtomicU64, Ordering};
/// use opcua_core::comms::tap::{MessageTap, TappedChunk};
///
/// #[derive(Default)]
/// struct ByteCounter(AtomicU64);
///
/// impl MessageTap for ByteCounter {
///     fn on_chunk(&self, chunk: &TappedChunk<'_>) {
///         self.0.fetch_add(chunk.bytes.len() as u64, Ordering::Relaxed);
///     }
/// }
/// ```
pub trait MessageTap: Send + Sync + 'static {
    /// Called once for every plaintext chunk that is sent or received. The chunk only lives
    /// for the duration of the call, copy what you need to keep.
    fn on_chunk(&self, chunk: &TappedChunk<'_>);
}

impl<F> MessageTap for F
where
    F: for<'a, 'b> Fn(&'a TappedChunk<'b>) + Send + Sync + 'static,
{
    fn on_chunk(&self, chunk: &TappedChunk<'_>) {
        self(chunk)
    }
}
