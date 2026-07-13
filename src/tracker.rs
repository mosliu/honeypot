use lru::LruCache;
use std::{
    collections::VecDeque,
    net::IpAddr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VisitDecision {
    Allow { count: usize },
    Ban { count: usize },
}

#[derive(Debug)]
pub struct VisitTracker {
    window: Duration,
    max_visits: usize,
    visits: LruCache<IpAddr, VecDeque<Instant>>,
}

impl VisitTracker {
    pub fn new(window: Duration, max_visits: usize, max_tracked_ips: usize) -> Self {
        assert!(max_visits > 0, "max_visits must be greater than 0");
        let max_tracked_ips =
            NonZeroUsize::new(max_tracked_ips).expect("max_tracked_ips must be greater than 0");

        Self {
            window,
            max_visits,
            visits: LruCache::new(max_tracked_ips),
        }
    }

    pub fn record(&mut self, ip: IpAddr) -> VisitDecision {
        self.record_at(ip, Instant::now())
    }

    pub fn record_at(&mut self, ip: IpAddr, now: Instant) -> VisitDecision {
        if !self.visits.contains(&ip) {
            self.visits.put(ip, VecDeque::new());
        }

        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let entry = self
            .visits
            .get_mut(&ip)
            .expect("visit entry must exist after insertion");
        while entry.front().is_some_and(|seen_at| *seen_at < cutoff) {
            entry.pop_front();
        }

        if entry.len() == self.max_visits {
            entry.pop_front();
        }
        entry.push_back(now);
        let count = entry.len();
        if count >= self.max_visits {
            VisitDecision::Ban { count }
        } else {
            VisitDecision::Allow { count }
        }
    }

    pub fn tracked_ip_count(&self) -> usize {
        self.visits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn bans_on_configured_visit_count_inside_window() {
        let mut tracker = VisitTracker::new(Duration::from_secs(60), 3, 100);
        let start = Instant::now();

        assert_eq!(
            tracker.record_at(ip(10), start),
            VisitDecision::Allow { count: 1 }
        );
        assert_eq!(
            tracker.record_at(ip(10), start + Duration::from_secs(1)),
            VisitDecision::Allow { count: 2 }
        );
        assert_eq!(
            tracker.record_at(ip(10), start + Duration::from_secs(2)),
            VisitDecision::Ban { count: 3 }
        );
    }

    #[test]
    fn old_visits_expire_outside_window() {
        let mut tracker = VisitTracker::new(Duration::from_secs(10), 2, 100);
        let start = Instant::now();

        assert_eq!(
            tracker.record_at(ip(10), start),
            VisitDecision::Allow { count: 1 }
        );
        assert_eq!(
            tracker.record_at(ip(10), start + Duration::from_secs(11)),
            VisitDecision::Allow { count: 1 }
        );
    }

    #[test]
    fn evicts_least_recently_used_ip_when_tracking_table_is_full() {
        let mut tracker = VisitTracker::new(Duration::from_secs(60), 10, 2);
        let start = Instant::now();

        tracker.record_at(ip(1), start);
        tracker.record_at(ip(2), start + Duration::from_secs(1));
        tracker.record_at(ip(1), start + Duration::from_secs(2));
        tracker.record_at(ip(3), start + Duration::from_secs(3));

        assert_eq!(tracker.tracked_ip_count(), 2);
        assert!(tracker.visits.contains(&ip(1)));
        assert!(!tracker.visits.contains(&ip(2)));
        assert!(tracker.visits.contains(&ip(3)));
    }

    #[test]
    fn bounds_stored_events_for_one_ip_after_repeated_bans() {
        let mut tracker = VisitTracker::new(Duration::from_secs(1_000), 3, 100);
        let start = Instant::now();

        for offset in 0..100 {
            let decision = tracker.record_at(ip(10), start + Duration::from_secs(offset));
            if offset >= 2 {
                assert_eq!(decision, VisitDecision::Ban { count: 3 });
            }
        }

        assert_eq!(tracker.visits.get(&ip(10)).unwrap().len(), 3);
    }

    #[test]
    fn banned_ip_recovers_after_its_stored_events_expire() {
        let mut tracker = VisitTracker::new(Duration::from_secs(10), 3, 100);
        let start = Instant::now();

        tracker.record_at(ip(10), start);
        tracker.record_at(ip(10), start + Duration::from_secs(1));
        assert_eq!(
            tracker.record_at(ip(10), start + Duration::from_secs(2)),
            VisitDecision::Ban { count: 3 }
        );
        assert_eq!(
            tracker.record_at(ip(10), start + Duration::from_secs(13)),
            VisitDecision::Allow { count: 1 }
        );
    }

    #[test]
    fn never_exceeds_the_configured_ip_capacity() {
        let mut tracker = VisitTracker::new(Duration::from_secs(60), 3, 8);
        let start = Instant::now();

        for last in 0..100 {
            tracker.record_at(ip(last), start + Duration::from_secs(u64::from(last)));
            assert!(tracker.tracked_ip_count() <= 8);
        }

        assert_eq!(tracker.tracked_ip_count(), 8);
    }
}
