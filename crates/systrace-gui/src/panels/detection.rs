use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Category colours
// ---------------------------------------------------------------------------

const COLOR_ANTI_FORENSICS: Color32 = Color32::from_rgb(220, 80, 80);   // red
const COLOR_DEFENSE_EVASION: Color32 = Color32::from_rgb(220, 150, 40); // orange
const COLOR_WMI: Color32           = Color32::from_rgb(160, 80, 220);  // purple
const COLOR_DATA_ACCESS: Color32   = Color32::from_rgb(80, 180, 220);  // cyan

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum DetectionCategory {
    AntiForensics,
    DefenseEvasion,
    WmiPersistence,
    DataAccess,
}

impl DetectionCategory {
    fn label(&self) -> &'static str {
        match self {
            Self::AntiForensics   => "Anti-Forensics",
            Self::DefenseEvasion  => "Defense Evasion",
            Self::WmiPersistence  => "WMI Persistence",
            Self::DataAccess      => "Data Access",
        }
    }
    fn color(&self) -> Color32 {
        match self {
            Self::AntiForensics   => COLOR_ANTI_FORENSICS,
            Self::DefenseEvasion  => COLOR_DEFENSE_EVASION,
            Self::WmiPersistence  => COLOR_WMI,
            Self::DataAccess      => COLOR_DATA_ACCESS,
        }
    }
}

struct DetectionRow {
    time: Timestamp,
    category: DetectionCategory,
    event_type: String, // human name of event
    col_a: String,      // primary detail column (context-dependent)
    col_b: String,      // secondary detail
    col_c: String,      // tertiary detail
    mitre: String,
}

impl DetectionRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.event_type,
            self.col_a,
            self.col_b,
            self.col_c,
            self.category.label(),
            self.mitre,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_detection_table(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let event_ids: &[u16] = &[2, 4, 9, 16, 19, 20, 21, 24];
    let indices = event_store.events_for_process_and_types(&guid, event_ids);
    if indices.is_empty() {
        render_empty(ui, "No detection events for this process.");
        return;
    }

    // Build typed rows
    let mut rows: Vec<DetectionRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            match &ev.detail {
                // EventId 2: FileCreateTime — Anti-Forensics
                EventDetail::FileCreateTime {
                    target_filename,
                    creation_utc_time,
                    previous_creation_utc_time,
                } => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::AntiForensics,
                    event_type: "FileCreateTime".to_owned(),
                    col_a: target_filename.clone().unwrap_or_default(),
                    col_b: creation_utc_time.clone().unwrap_or_default(),
                    col_c: previous_creation_utc_time.clone().unwrap_or_default(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                // EventId 9: RawAccessRead — Anti-Forensics
                EventDetail::RawAccessRead { device } => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::AntiForensics,
                    event_type: "RawAccessRead".to_owned(),
                    col_a: device.clone().unwrap_or_default(),
                    col_b: String::new(),
                    col_c: String::new(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                // EventId 4: SysmonServiceState — Defense Evasion (stored as Generic)
                EventDetail::Generic { fields } if ev.event_id == 4 => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::DefenseEvasion,
                    event_type: "SysmonState".to_owned(),
                    col_a: fields.get("State").cloned().unwrap_or_default(),
                    col_b: fields.get("Version").cloned().unwrap_or_default(),
                    col_c: String::new(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                // EventId 16: SysmonConfigChange — Defense Evasion
                EventDetail::SysmonConfigChange {
                    configuration,
                    configuration_file_hash,
                } => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::DefenseEvasion,
                    event_type: "ConfigChange".to_owned(),
                    col_a: configuration.clone().unwrap_or_default(),
                    col_b: configuration_file_hash.clone().unwrap_or_default(),
                    col_c: String::new(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                // EventId 19-21: WmiActivity — WMI Persistence
                EventDetail::WmiActivity {
                    event_type,
                    operation,
                    name,
                    query,
                    destination,
                    ..
                } => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::WmiPersistence,
                    event_type: event_type.clone(),
                    col_a: operation.clone().unwrap_or_default(),
                    col_b: name.clone()
                        .or_else(|| query.clone())
                        .unwrap_or_default(),
                    col_c: destination.clone().unwrap_or_default(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                // EventId 24: ClipboardChange — Data Access
                EventDetail::ClipboardChange {
                    session,
                    client_info,
                    hashes,
                } => Some(DetectionRow {
                    time: ev.time_created,
                    category: DetectionCategory::DataAccess,
                    event_type: "ClipboardChange".to_owned(),
                    col_a: session.clone().unwrap_or_default(),
                    col_b: client_info.clone().unwrap_or_default(),
                    col_c: hashes.clone().unwrap_or_default(),
                    mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                }),

                _ => None,
            }
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
        render_empty(ui, "No matching detection events.");
        return;
    }

    // Sort
    let sort_col = tab.sort.column;
    let sort_asc = tab.sort.ascending;
    match sort_col {
        0 => rows.sort_by(|a, b| cmp_ord(a.time.cmp(&b.time), sort_asc)),
        1 => rows.sort_by(|a, b| cmp_ord(a.event_type.cmp(&b.event_type), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.col_a.cmp(&b.col_a), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.col_b.cmp(&b.col_b), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.col_c.cmp(&b.col_c), sort_asc)),
        5 => rows.sort_by(|a, b| cmp_ord(a.mitre.cmp(&b.mitre), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(
        &["Time", "Event", "Detail A", "Detail B", "Detail C", "MITRE"],
        &tab.sort,
    );

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    // Category legend
    ui.horizontal(|ui| {
        for (color, label) in [
            (COLOR_ANTI_FORENSICS, "Anti-Forensics"),
            (COLOR_DEFENSE_EVASION, "Defense Evasion"),
            (COLOR_WMI, "WMI Persistence"),
            (COLOR_DATA_ACCESS, "Data Access"),
        ] {
            let rect = ui.label(RichText::new("■").color(color)).rect;
            let _ = rect;
            ui.label(label);
            ui.add_space(6.0);
        }
    });
    ui.separator();

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))  // Time
            .column(Column::initial(130.0).clip(true))  // Event
            .column(Column::initial(200.0).clip(true))  // Detail A
            .column(Column::initial(200.0).clip(true))  // Detail B
            .column(Column::initial(120.0).clip(true))  // Detail C
            .column(Column::remainder().clip(true).at_least(80.0))  // MITRE
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
                    let cat_color = r.category.color();
                    row.set_selected(selected == Some(i));

                    row.col(|ui| { ui.label(fmt_time(r.time)); });
                    row.col(|ui| {
                        ui.label(RichText::new(&r.event_type).color(cat_color));
                    });
                    row.col(|ui| { ui.label(&r.col_a); });
                    row.col(|ui| { ui.label(&r.col_b); });
                    row.col(|ui| { ui.label(&r.col_c); });
                    row.col(|ui| {
                        if !r.mitre.is_empty() {
                            ui.colored_label(egui::Color32::from_rgb(220, 120, 60), &r.mitre);
                        }
                    });

                    let resp = row.response();
                    if resp.clicked() {
                        next_selected = Some(i);
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Copy Row").clicked() {
                            ui.ctx().copy_text(r.copy_text());
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Copy Time").clicked() {
                            ui.ctx().copy_text(fmt_time(r.time));
                            ui.close_menu();
                        }
                        if ui.button("Copy Event").clicked() {
                            ui.ctx().copy_text(r.event_type.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Detail A").clicked() {
                            ui.ctx().copy_text(r.col_a.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Detail B").clicked() {
                            ui.ctx().copy_text(r.col_b.clone());
                            ui.close_menu();
                        }
                        if !r.col_c.is_empty() {
                            if ui.button("Copy Detail C").clicked() {
                                ui.ctx().copy_text(r.col_c.clone());
                                ui.close_menu();
                            }
                        }
                        if !r.mitre.is_empty() && ui.button("Copy MITRE").clicked() {
                            ui.ctx().copy_text(r.mitre.clone());
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
}
