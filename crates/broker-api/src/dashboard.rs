//! Embedded management console: a zero-dependency dark-mode SPA served
//! from memory (no runtime asset files, no Node/NPM build step).

/// The full single-page console, inlined at compile time.
pub const DASHBOARD_HTML: &str = include_str!("dashboard.html");
