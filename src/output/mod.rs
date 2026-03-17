pub mod terminal;
pub mod json;
pub mod html;

use crate::models::ScanReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Json,
    Html,
}

pub fn render(report: &ScanReport, format: OutputFormat) -> String {
    match format {
        OutputFormat::Terminal => terminal::render(report),
        OutputFormat::Json => json::render(report),
        OutputFormat::Html => html::render(report),
    }
}
