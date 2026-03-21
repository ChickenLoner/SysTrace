//! Sigma rule matches panel — global view of all rule hits across all processes.

use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use systrace_core::{SigmaLevel, SigmaMatch, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Level color
// ---------------------------------------------------------------------------

fn level_color(level: SigmaLevel) -> Color32 {
    match level {
        SigmaLevel::Critical      => Color32::from_rgb(220, 60, 60),
        SigmaLevel::High          => Color32::from_rgb(220, 140, 40),
        SigmaLevel::Medium        => Color32::from_rgb(200, 200, 60),
        SigmaLevel::Low           => Color32::from_rgb(80, 160, 220),
        SigmaLevel::Informational => Color32::from_rgb(160, 160, 160),
    }
}

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct SigmaRow {
    time:        Timestamp,
    level:       SigmaLevel,
    rule_title:  String,
    event_id:    u16,
    process:     String,
    match_index: usize,   // index into original sigma_matches for navigation
}

impl SigmaRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.level.label(),
            self.rule_title,
            self.event_id,
            self.process,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

/// `select_process_idx` is set by this function when the user clicks a row.
/// The caller must translate the returned index into a ProcessGuid navigation.
pub fn render_sigma(
    ui: &mut egui::Ui,
    matches: &[SigmaMatch],
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
    process_name_fn: &dyn Fn(usize) -> String,
    no_rules: bool,
) -> Option<usize> {
    if no_rules {
        render_empty(ui, "No sigma rules loaded. Use \"Import Rule\" or \"Import Folder\" above.");
        return None;
    }
    if matches.is_empty() {
        render_empty(ui, "No matches. Rules are loaded but no events triggered them.");
        return None;
    }

    let mut rows: Vec<SigmaRow> = matches
        .iter()
        .enumerate()
        .map(|(i, m)| SigmaRow {
            time:        m.timestamp,
            level:       m.level,
            rule_title:  m.rule_title.clone(),
            event_id:    m.event_id,
            process:     process_name_fn(i),
            match_index: i,
        })
        .collect();

    if !filter.is_empty() {
        let f = filter.to_lowercase();
        rows.retain(|r| r.copy_text().to_lowercase().contains(&f));
    }
    if let Some((t_from, t_to)) = time_range {
        rows.retain(|r| r.time >= t_from && r.time <= t_to);
    }
    if rows.is_empty() {
        render_empty(ui, "No matching sigma alerts.");
        return None;
    }

    let sort_col = tab.sort.column;
    let sort_asc = tab.sort.ascending;
    match sort_col {
        0 => rows.sort_by(|a, b| cmp_ord(a.time.cmp(&b.time), sort_asc)),
        1 => rows.sort_by(|a, b| cmp_ord(a.level.label().cmp(b.level.label()), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.rule_title.cmp(&b.rule_title), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.event_id.cmp(&b.event_id), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.process.cmp(&b.process), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(&["Time", "Level", "Rule", "EventID", "Process"], &tab.sort);

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let mut navigate_to: Option<usize> = None;
    let rows_ref = &rows;

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))   // Time
            .column(Column::initial(80.0).clip(true))    // Level
            .column(Column::initial(300.0).clip(true))   // Rule
            .column(Column::initial(70.0).clip(true))    // EventID
            .column(Column::remainder().clip(true).at_least(120.0)) // Process
            .header(20.0, |mut header| {
                for (i, h) in headers.iter().enumerate() {
                    header.col(|ui| {
                        if ui.button(h.as_str()).clicked() {
                            next_sort = Some(i);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, rows_ref.len(), |mut row| {
                    let i = row.index();
                    let r = &rows_ref[i];
                    row.set_selected(selected == Some(i));
                    let col = level_color(r.level);
                    row.col(|ui| { ui.label(fmt_time(r.time)); });
                    row.col(|ui| {
                        ui.label(RichText::new(r.level.label()).color(col).strong());
                    });
                    row.col(|ui| { ui.label(RichText::new(&r.rule_title).color(col)); });
                    row.col(|ui| { ui.label(r.event_id.to_string()); });
                    row.col(|ui| { ui.label(&r.process); });

                    let resp = row.response();
                    if resp.clicked() {
                        next_selected = Some(i);
                        navigate_to = Some(r.match_index);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Copy Row").clicked() {
                            ui.ctx().copy_text(r.copy_text());
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Copy Rule").clicked() {
                            ui.ctx().copy_text(r.rule_title.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Time").clicked() {
                            ui.ctx().copy_text(fmt_time(r.time));
                            ui.close_menu();
                        }
                        if ui.button("Go to Process").clicked() {
                            navigate_to = Some(r.match_index);
                            ui.close_menu();
                        }
                    });
                });
            });
    });

    if let Some(col) = next_sort {
        tab.sort.toggle(col);
    }
    tab.selected_row = next_selected;

    navigate_to
}
