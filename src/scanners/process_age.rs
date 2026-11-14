//! How long this process existed before `main` ran, for `ScanTiming::startup_ms`.

/// Milliseconds from the kernel starting this process to now: its start time
/// (`/proc/self/stat` field 22, clock ticks since boot) against `/proc/uptime`. Call it
/// first thing in `main` for the time spent before `main`. `None` off Linux or when
/// either file does not parse. The two files hold kernel counters only.
pub fn process_age_ms() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
        process_age_from(&stat, &uptime, crate::scanners::listeners::clock_ticks())
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// [`process_age_ms`] from the two files' text. The command name in `stat` is in
/// parentheses and may itself hold spaces and parentheses, so fields are counted from
/// the last `)`.
pub fn process_age_from(stat: &str, uptime: &str, clock_ticks: u64) -> Option<u64> {
    let after = &stat[stat.rfind(')')? + 1..];
    // Field 3 (state) is the first after the name; starttime is field 22.
    let start_ticks: u64 = after.split_ascii_whitespace().nth(19)?.parse().ok()?;
    let up_secs: f64 = uptime.split_ascii_whitespace().next()?.parse().ok()?;
    if clock_ticks == 0 || !up_secs.is_finite() || up_secs < 0.0 {
        return None;
    }
    let start_ms = start_ticks.saturating_mul(1000) / clock_ticks;
    Some(((up_secs * 1000.0) as u64).saturating_sub(start_ms))
}

#[cfg(test)]
mod tests {
    use super::process_age_from;

    #[test]
    fn age_is_uptime_minus_start_and_the_name_may_hold_parentheses() {
        let stat =
            "4242 (a b) c) S 1 4242 4242 0 -1 4194304 100 0 0 0 1 2 0 0 20 0 1 0 500000 1000 10 18446744073709551615";
        // 500000 ticks at 100/s = 5000.00 s; uptime 5000.25 s.
        assert_eq!(process_age_from(stat, "5000.25 9000.00\n", 100), Some(250));
        // A start "after" the uptime reading (tick rounding) is 0, not a huge number.
        assert_eq!(process_age_from(stat, "4999.99 1.0", 100), Some(0));
        assert_eq!(process_age_from("no parens", "1.0 1.0", 100), None);
        assert_eq!(process_age_from(stat, "", 100), None);
        assert_eq!(process_age_from(stat, "1.0", 0), None);
    }
}
