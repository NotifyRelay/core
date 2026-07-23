use ruopus::EncodeError;

const OPUS_BITRATE: u32 = 64000;
const OPUS_FRAME_SIZE: i32 = 960;

pub struct OpusEncoder {
    inner: ruopus::OpusEncoder,
    channels: i32,
    frame_size: i32,
}

impl OpusEncoder {
    pub fn new(_sample_rate: i32, channels: i32) -> Result<Self, EncodeError> {
        let mut inner = ruopus::OpusEncoder::new(channels as usize);
        inner.set_bitrate(Some(OPUS_BITRATE));
        Ok(Self {
            inner,
            channels,
            frame_size: OPUS_FRAME_SIZE,
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
        self.inner.encode_auto(&pcm_f32, 2048)
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }

    pub fn bitrate(&self) -> i32 {
        OPUS_BITRATE as i32
    }
}
