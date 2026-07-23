use ruopus::{Encoder as OpusEncoderInner, Channels, Application};

const OPUS_BITRATE: i32 = 64000;
const OPUS_FRAME_SIZE: i32 = 960;
const OPUS_COMPLEXITY: i32 = 5;

pub struct OpusEncoder {
    inner: OpusEncoderInner,
    channels: i32,
    frame_size: i32,
}

impl OpusEncoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, ruopus::Error> {
        let inner = OpusEncoderInner::new(
            sample_rate as u32,
            if channels == 1 {
                Channels::Mono
            } else {
                Channels::Stereo
            },
            Application::Audio,
        )?;
        Ok(Self {
            inner,
            channels,
            frame_size: OPUS_FRAME_SIZE,
        })
    }

    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, ruopus::Error> {
        let frame_samples = self.frame_size as usize * self.channels as usize;

        let chunk = if pcm.len() >= frame_samples {
            &pcm[..frame_samples]
        } else {
            pcm
        };

        if chunk.is_empty() {
            return Ok(Vec::new());
        }

        let mut output = vec![0u8; 2048];
        let len = self.inner.encode(chunk, &mut output)?;
        Ok(output[..len].to_vec())
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }

    pub fn bitrate(&self) -> i32 {
        OPUS_BITRATE
    }
}
