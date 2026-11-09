//! Bound common-ancestor searches by the indexed tip, including a shorter node chain.

/// Raw orphan evidence is optional and committed in one rollback transaction,
/// so a deep reorg of full blocks must not hold gigabytes of hex in memory.
pub const MAX_RAW_ORPHAN_HEX_BYTES: usize = 256 * 1024 * 1024;

pub struct RawCaptureBudget {
    remaining: usize,
}

impl RawCaptureBudget {
    pub fn new(bytes: usize) -> Self {
        Self { remaining: bytes }
    }

    /// Once a block does not fit, capture stops rather than skipping around it.
    pub fn admit(&mut self, hex_bytes: usize) -> bool {
        if hex_bytes > self.remaining {
            self.remaining = 0;
            return false;
        }
        self.remaining -= hex_bytes;
        true
    }

    pub fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
}

pub fn ancestor_heights(
    last_indexed: u32,
    node_tip: u32,
    max_depth: u32,
) -> Result<Vec<u32>, String> {
    let oldest = last_indexed.saturating_sub(max_depth);
    let newest = last_indexed.min(node_tip);
    if newest < oldest || max_depth == 0 {
        return Err(format!(
            "Reorg deeper than {max_depth} blocks — manual intervention required"
        ));
    }
    Ok((oldest..=newest).rev().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shorter_tip_never_requests_future_heights_and_counts_removed_tail() {
        assert_eq!(ancestor_heights(100, 99, 3).unwrap(), vec![99, 98, 97]);
        assert_eq!(
            ancestor_heights(100, 101, 3).unwrap(),
            vec![100, 99, 98, 97]
        );
        assert_eq!(ancestor_heights(100, 97, 3).unwrap(), vec![97]);
        assert!(ancestor_heights(100, 96, 3).is_err());
        assert_eq!(ancestor_heights(1, 0, 5).unwrap(), vec![0]);
    }

    #[test]
    fn default_depth_reaches_the_node_rollback_limit() {
        let depth = crate::config::Config::default().max_reorg_depth;
        assert_eq!(depth, 1000);
        let heights = ancestor_heights(5_000, 5_000, depth).unwrap();
        assert_eq!(heights.len(), 1001);
        assert_eq!(heights.last(), Some(&4_000));
    }

    #[test]
    fn raw_capture_stops_at_the_first_block_over_budget() {
        let mut budget = RawCaptureBudget::new(10);
        assert!(budget.admit(6));
        assert!(!budget.is_exhausted());
        assert!(!budget.admit(5));
        assert!(budget.is_exhausted());
        assert!(!budget.admit(1), "later blocks must not fill the gap");
    }

    #[test]
    fn raw_capture_budget_is_exhausted_when_exactly_filled() {
        let mut budget = RawCaptureBudget::new(4);
        assert!(budget.admit(4));
        assert!(budget.is_exhausted());
    }
}
