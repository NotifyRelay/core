use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const DEFAULT_JITTER_DEPTH_MS: u64 = 100;

pub struct JitterBuffer {
    packets: BTreeMap<u16, (Vec<u8>, Instant)>,
    last_seq: Option<u16>,
    jitter_depth: Duration,
}

impl JitterBuffer {
    pub fn new() -> Self {
        Self {
            packets: BTreeMap::new(),
            last_seq: None,
            jitter_depth: Duration::from_millis(DEFAULT_JITTER_DEPTH_MS),
        }
    }

    pub fn push(&mut self, seq: u16, data: Vec<u8>) {
        let now = Instant::now();
        self.packets.insert(seq, (data, now));
        self.cleanup(now);
    }

    fn cleanup(&mut self, now: Instant) {
        self.packets
            .retain(|_, (_, ts)| now.duration_since(*ts) <= self.jitter_depth);
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        let now = Instant::now();
        self.cleanup(now);

        let next_seq = match self.last_seq {
            Some(s) => s.wrapping_add(1),
            None => {
                if let Some((&first_seq, _)) = self.packets.iter().next() {
                    first_seq
                } else {
                    return None;
                }
            }
        };

        match self.packets.remove(&next_seq) {
            Some((data, _)) => {
                self.last_seq = Some(next_seq);
                Some(data)
            }
            None => None,
        }
    }

    pub fn pop_with_gap(&mut self) -> (Option<Vec<u8>>, u64) {
        let now = Instant::now();
        self.cleanup(now);

        if self.packets.is_empty() {
            return (None, 0);
        }

        let next_seq = match self.last_seq {
            Some(s) => s.wrapping_add(1),
            None => {
                if let Some((&first_seq, _)) = self.packets.iter().next() {
                    first_seq
                } else {
                    return (None, 0);
                }
            }
        };

        if let Some((data, _)) = self.packets.remove(&next_seq) {
            self.last_seq = Some(next_seq);
            return (Some(data), 0);
        }

        let first_available = *self.packets.keys().next().unwrap();
        let gap_size = first_available.wrapping_sub(next_seq);

        if gap_size > 0 && gap_size < 1000 {
            self.last_seq = Some(first_available.wrapping_sub(1));
            (None, gap_size as u64)
        } else {
            (None, 0)
        }
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn reset(&mut self) {
        self.packets.clear();
        self.last_seq = None;
    }
}
