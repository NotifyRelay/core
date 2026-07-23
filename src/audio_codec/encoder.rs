use ruopus::EncodeError;

const OPUS_BITRATE: u32 = 64000;
const OPUS_FRAME_MS: i32 = 20;

pub struct OpusEncoder {
    inner: ruopus::OpusEncoder,
    channels: i32,
    frame_size: i32,
    sample_rate: i32,
}

impl OpusEncoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, EncodeError> {
        let frame_size = (sample_rate * OPUS_FRAME_MS) / 1000;
        let mut inner = ruopus::OpusEncoder::new(channels as usize);
        inner.set_bitrate(Some(OPUS_BITRATE));
        Ok(Self {
            inner,
            channels,
            frame_size,
            sample_rate,
        })
    }

    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, EncodeError> {
        let frame_samples = self.frame_size as usize * self.channels as usize;

        let chunk = if pcm.len() >= frame_samples {
            &pcm[..frame_samples]
        } else {
            pcm
        };

        if chunk.is_empty() {
            return Ok(Vec::new());
        }

        let pcm_f32: Vec<f32> = chunk.iter().map(|&x| x as f32 / 32768.0).collect();
        self.inner.encode_auto(&pcm_f32, 1275)
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }

    pub fn bitrate(&self) -> i32 {
        OPUS_BITRATE as i32
    }
}
