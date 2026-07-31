const OPUS_FRAME_MS: i32 = 20;

pub struct OpusDecoder {
    inner: ruopus::OpusDecoder,
    channels: i32,
    frame_size: i32,
    sample_rate: i32,
    pcm_i16_buffer: Vec<i16>,
}

impl OpusDecoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, ruopus::packet::PacketError> {
        let frame_size = (sample_rate * OPUS_FRAME_MS) / 1000;
        let frame_samples = (frame_size as usize) * (channels as usize);
        let inner = ruopus::OpusDecoder::new(channels as usize);
        Ok(Self {
            inner,
            channels,
            frame_size,
            sample_rate,
            pcm_i16_buffer: vec![0i16; frame_samples],
        })
    }

    #[inline]
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, ruopus::packet::PacketError> {
        let output_len = (self.frame_size * self.channels) as usize;
        if data.is_empty() {
            self.pcm_i16_buffer.iter_mut().take(output_len).for_each(|s| *s = 0);
            return Ok(self.pcm_i16_buffer[..output_len].to_vec());
        }

        let pcm_f32 = self.inner.decode_packet(data)?;
        let out = &mut self.pcm_i16_buffer[..pcm_f32.len()];
        for (i, &s) in pcm_f32.iter().enumerate() {
            out[i] = (s * 32768.0) as i16;
        }
        Ok(out.to_vec())
    }

    #[inline]
    pub fn decode_loss(&mut self) -> Result<Vec<i16>, ruopus::packet::PacketError> {
        let frame_samples = self.frame_size as usize * self.channels as usize;

        let pcm_f32 = self.inner.decode_lost(frame_samples);
        let out = &mut self.pcm_i16_buffer[..pcm_f32.len()];
        for (i, &s) in pcm_f32.iter().enumerate() {
            out[i] = (s * 32768.0) as i16;
        }
        Ok(out.to_vec())
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }
}
