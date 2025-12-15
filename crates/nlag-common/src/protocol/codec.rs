//! Message codec for framing protocol messages
//!
//! This module implements length-prefixed framing for the NLAG protocol.
//! All messages are serialized with bincode and prefixed with their length.
//!
//! ## Frame Format
//!
//! ```text
//! +----------------+----------------+------------------+
//! | Length (4B BE) | Version (1B)   | Payload (N bytes)|
//! +----------------+----------------+------------------+
//! ```

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::error::{NlagError, Result};
use crate::protocol::{
    message::Message, CURRENT_PROTOCOL_VERSION, MAX_MESSAGE_SIZE, MIN_MESSAGE_SIZE,
};

/// Codec for encoding and decoding NLAG protocol messages
///
/// This codec handles:
/// - Length-prefix framing
/// - Protocol version validation
/// - Message serialization/deserialization
#[derive(Debug, Clone)]
pub struct MessageCodec {
    /// Maximum allowed message size
    max_size: usize,
    /// Expected protocol version (for validation)
    expected_version: u8,
}

impl MessageCodec {
    /// Create a new codec with default settings
    pub fn new() -> Self {
        Self {
            max_size: MAX_MESSAGE_SIZE,
            expected_version: CURRENT_PROTOCOL_VERSION,
        }
    }

    /// Create a codec with custom max message size
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Encode a message to bytes (without framing)
    pub fn encode_message(msg: &Message) -> Result<Bytes> {
        let payload = bincode::serialize(msg)?;
        Ok(Bytes::from(payload))
    }

    /// Decode a message from bytes (without framing)
    pub fn decode_message(data: &[u8]) -> Result<Message> {
        let msg = bincode::deserialize(data)?;
        Ok(msg)
    }
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = NlagError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // Need at least the length prefix
        if src.len() < 4 {
            return Ok(None);
        }

        // Peek at the length (don't consume yet)
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        // Validate length
        if length < MIN_MESSAGE_SIZE - 4 {
            return Err(NlagError::MalformedMessage(format!(
                "Message too small: {} bytes",
                length
            )));
        }

        if length > self.max_size {
            return Err(NlagError::MessageTooLarge {
                size: length,
                max: self.max_size,
            });
        }

        // Check if we have the full message
        let total_size = 4 + length;
        if src.len() < total_size {
            // Reserve space for the rest of the message
            src.reserve(total_size - src.len());
            return Ok(None);
        }

        // Consume the length prefix
        src.advance(4);

        // Read version byte
        let version = src[0];
        if version != self.expected_version {
            return Err(NlagError::ProtocolVersionMismatch {
                expected: self.expected_version,
                actual: version,
            });
        }
        src.advance(1);

        // Read the payload (length - 1 for version byte)
        let payload = src.split_to(length - 1);

        // Deserialize the message
        let msg = bincode::deserialize(&payload)?;

        Ok(Some(msg))
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = NlagError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        // Serialize the message
        let payload = bincode::serialize(&item)?;

        // Calculate total length (version byte + payload)
        let length = 1 + payload.len();

        if length > self.max_size {
            return Err(NlagError::MessageTooLarge {
                size: length,
                max: self.max_size,
            });
        }

        // Reserve space
        dst.reserve(4 + length);

        // Write length prefix
        dst.put_u32(length as u32);

        // Write version
        dst.put_u8(CURRENT_PROTOCOL_VERSION);

        // Write payload
        dst.put_slice(&payload);

        Ok(())
    }
}

/// Async message reading/writing utilities for QUIC streams
pub mod quic {
    use super::*;
    use quinn::{RecvStream, SendStream};

    /// Read a single message from a QUIC receive stream
    pub async fn read_message(recv: &mut RecvStream) -> Result<Message> {
        // Read length prefix
        let mut length_buf = [0u8; 4];
        recv.read_exact(&mut length_buf)
            .await
            .map_err(|e| NlagError::QuicError(format!("Failed to read length: {}", e)))?;

        let length = u32::from_be_bytes(length_buf) as usize;

        // Validate length
        if length > MAX_MESSAGE_SIZE {
            return Err(NlagError::MessageTooLarge {
                size: length,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Read message body (version + payload)
        let mut body = vec![0u8; length];
        recv.read_exact(&mut body)
            .await
            .map_err(|e| NlagError::QuicError(format!("Failed to read body: {}", e)))?;

        // Validate version
        let version = body[0];
        if version != CURRENT_PROTOCOL_VERSION {
            return Err(NlagError::ProtocolVersionMismatch {
                expected: CURRENT_PROTOCOL_VERSION,
                actual: version,
            });
        }

        // Deserialize message
        let msg = bincode::deserialize(&body[1..])?;
        Ok(msg)
    }

    /// Write a single message to a QUIC send stream
    pub async fn write_message(send: &mut SendStream, msg: &Message) -> Result<()> {
        // Serialize message
        let payload = bincode::serialize(msg)?;

        // Calculate length (version + payload)
        let length = 1 + payload.len();

        if length > MAX_MESSAGE_SIZE {
            return Err(NlagError::MessageTooLarge {
                size: length,
                max: MAX_MESSAGE_SIZE,
            });
        }

        // Build the frame
        let mut frame = Vec::with_capacity(4 + length);
        frame.extend_from_slice(&(length as u32).to_be_bytes());
        frame.push(CURRENT_PROTOCOL_VERSION);
        frame.extend_from_slice(&payload);

        // Write frame
        send.write_all(&frame)
            .await
            .map_err(|e| NlagError::QuicError(format!("Failed to write: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::message::{PingMessage, PongMessage};

    #[test]
    fn test_codec_roundtrip() {
        let mut codec = MessageCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::Ping(PingMessage {
            timestamp: 12345678,
            seq: 42,
        });

        // Encode
        codec.encode(msg.clone(), &mut buf).unwrap();

        // Decode
        let decoded = codec.decode(&mut buf).unwrap().unwrap();

        match decoded {
            Message::Ping(ping) => {
                assert_eq!(ping.timestamp, 12345678);
                assert_eq!(ping.seq, 42);
            }
            _ => panic!("Wrong message type"),
        }
    }

    #[test]
    fn test_codec_partial_read() {
        let mut codec = MessageCodec::new();
        let mut buf = BytesMut::new();

        let msg = Message::Pong(PongMessage {
            timestamp: 999,
            seq: 1,
        });

        // Encode full message
        let mut full_buf = BytesMut::new();
        codec.encode(msg, &mut full_buf).unwrap();

        // Feed partial data
        buf.extend_from_slice(&full_buf[..4]); // Just length prefix
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Feed rest
        buf.extend_from_slice(&full_buf[4..]);
        assert!(codec.decode(&mut buf).unwrap().is_some());
    }

    #[test]
    fn test_message_too_large() {
        let mut codec = MessageCodec::new().with_max_size(100);
        let mut buf = BytesMut::new();

        // Create a large message
        let msg = Message::Data(crate::protocol::message::DataFrame {
            tunnel_id: crate::types::TunnelId::new(),
            stream_id: crate::types::StreamId(1),
            payload: vec![0u8; 1000],
        });

        let result = codec.encode(msg, &mut buf);
        assert!(matches!(result, Err(NlagError::MessageTooLarge { .. })));
    }
}
