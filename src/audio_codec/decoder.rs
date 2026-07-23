const OPUS_FRAME_MS: i32 = 20;

pub struct OpusDecoder {
    inner: ruopus::OpusDecoder,
    channels: i32,
    frame_size: i32,
    sample_rate: i32,
}

impl OpusDecoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, ruopus::packet::PacketError> {
        let frame_size = (sample_rate * OPUS_FRAME_MS) / 1000;
        let inner = ruopus::OpusDecoder::new(channels as usize);
        Ok(Self {
            inner,
            channels,
            frame_size,
            sample_rate,
        })
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, ruopus::packet::PacketError> {
        if data.is_empty() {
            let output_len = (self.frame_size * self.channels) as usize;
            return Ok(vec![0i16; output_len]);
        }

        let pcm_f32 = self.inner.decode_packet(data)?;
        let pcm_i16: Vec<i16> = pcm_f32.iter().map(|&x| (x * 32768.0) as i16).collect();
        Ok(pcm_i16)
    }

    pub fn decode_loss(&mut self) -> Result<Vec<i16>, ruopus::packet::PacketError> {
        let frame_samples = self.frame_size as usize * self.channels as usize;
        
        let pcm_f32 = self.inner.decode_lost(frame_samples);
        let pcm_i16: Vec<i16> = pcm_f32.iter().map(|&x| (x * 32768.0) as i16).collect();
        Ok(pcm_i16)
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }
}
