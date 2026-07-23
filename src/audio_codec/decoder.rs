use opus::{Channels, Decoder as OpusDecoderInner, Error};

const OPUS_FRAME_SIZE: i32 = 960;

pub struct OpusDecoder {
    inner: OpusDecoderInner,
    channels: i32,
    frame_size: i32,
}

impl OpusDecoder {
    pub fn new(sample_rate: i32, channels: i32) -> Result<Self, Error> {
        let inner = OpusDecoderInner::new(
            sample_rate as u32,
            if channels == 1 {
                Channels::Mono
            } else {
                Channels::Stereo
            },
        )?;
        Ok(Self {
            inner,
            channels,
            frame_size: OPUS_FRAME_SIZE,
        })
    }

    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, Error> {
        let mut output = vec![0i16; (self.frame_size * self.channels) as usize];
        if data.is_empty() {
            let _ = self.inner.decode(&[], &mut output, false)?;
            Ok(output)
        } else {
            let len = self.inner.decode(data, &mut output, false)?;
            Ok(output[..len].to_vec())
        }
    }

    pub fn decode_loss(&mut self) -> Result<Vec<i16>, Error> {
        let mut output = vec![0i16; (self.frame_size * self.channels) as usize];
        let _ = self.inner.decode(&[], &mut output, false)?;
        Ok(output)
    }

    pub fn frame_size(&self) -> i32 {
        self.frame_size
    }
}
