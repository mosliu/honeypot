use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
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
    max_tracked_ips: usize,
    visits: HashMap<IpAddr, VecDeque<Instant>>,
    events_since_sweep: usize,
}

impl VisitTracker {
    pub fn new(window: Duration, max_visits: usize, max_tracked_ips: usize) -> Self {
        Self {
            window,
            max_visits,
            max_tracked_ips,
            visits: HashMap::new(),
            events_since_sweep: 0,
        }
    }

    pub fn record(&mut self, ip: IpAddr) -> VisitDecision {
        self.record_at(ip, Instant::now())
    }

    pub fn record_at(&mut self, ip: IpAddr, now: Instant) -> VisitDecision {
        self.events_since_sweep += 1;
        if self.events_since_sweep >= self.max_tracked_ips.min(10_000) {
            self.sweep(now);
        }

        if self.visits.len() >= self.max_tracked_ips && !self.visits.contains_key(&ip) {
            self.sweep(now);
            self.trim_to_limit();
        }

        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        let entry = self.visits.entry(ip).or_default();
        while entry.front().is_some_and(|seen_at| *seen_at < cutoff) {
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

    fn sweep(&mut self, now: Instant) {
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        for visits in self.visits.values_mut() {
            while visits.front().is_some_and(|seen_at| *seen_at < cutoff) {
                visits.pop_front();
            }
        }
        self.visits.retain(|_, visits| !visits.is_empty());
        self.events_since_sweep = 0;
    }

    fn trim_to_limit(&mut self) {
        if self.visits.len() < self.max_tracked_ips {
            return;
        }

        let remove_count = self.visits.len() - self.max_tracked_ips + 1;
        let mut oldest: Vec<(IpAddr, Instant)> = self
            .visits
            .iter()
            .filter_map(|(ip, visits)| visits.back().copied().map(|last_seen| (*ip, last_seen)))
            .collect();
        oldest.sort_by_key(|(_, last_seen)| *last_seen);

        for (ip, _) in oldest.into_iter().take(remove_count) {
            self.visits.remove(&ip);
        }
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
    fn evicts_oldest_ips_when_tracking_table_is_full() {
        let mut tracker = VisitTracker::new(Duration::from_secs(60), 10, 2);
        let start = Instant::now();

        tracker.record_at(ip(1), start);
        tracker.record_at(ip(2), start + Duration::from_secs(1));
        tracker.record_at(ip(3), start + Duration::from_secs(2));

        assert_eq!(tracker.tracked_ip_count(), 2);
    }
}
