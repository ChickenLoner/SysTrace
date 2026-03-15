use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct RegistryRow {
    time: Timestamp,
    action: String,
    target_object: String,
    details: String,
    mitre: String,
}

impl RegistryRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.action,
            self.target_object,
            self.details,
            self.mitre,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_registry(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let indices = event_store.events_for_process_and_types(&guid, &[12, 13, 14]);
    if indices.is_empty() {
        render_empty(ui, "No registry events for this process.");
        return;
    }

    let mut rows: Vec<RegistryRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            match &ev.detail {
                EventDetail::RegistryEvent {
                    event_type,
                    target_object,
                    details,
                    new_name,
                } => {
                    let action = event_type.clone().unwrap_or_default();
                    // For renames, append the new name to details
                    let detail_str = if let Some(name) = new_name {
                        format!("→ {}", name)
                    } else {
                        details.clone().unwrap_or_default()
                    };
                    Some(RegistryRow {
                        time: ev.time_created,
                        action,
                        target_object: target_object.clone().unwrap_or_default(),
                        details: detail_str,
                        mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                    })
                }
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
        render_empty(ui, "No matching events.");
        return;
    }

    let sort_col = tab.sort.column;
    let sort_asc = tab.sort.ascending;
    match sort_col {
        0 => rows.sort_by(|a, b| cmp_ord(a.time.cmp(&b.time), sort_asc)),
        1 => rows.sort_by(|a, b| cmp_ord(a.action.cmp(&b.action), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.target_object.cmp(&b.target_object), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.details.cmp(&b.details), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.mitre.cmp(&b.mitre), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(&["Time", "Action", "Target Object", "Details", "MITRE"], &tab.sort);

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))  // Time
            .column(Column::initial(130.0).clip(true))  // Action
            .column(Column::initial(260.0).clip(true))  // Key / Target
            .column(Column::initial(220.0).clip(true))  // Value
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
                    row.set_selected(selected == Some(i));
                    row.col(|ui| { ui.label(fmt_time(r.time)); });
                    row.col(|ui| { ui.label(&r.action); });
                    row.col(|ui| { ui.label(&r.target_object); });
                    row.col(|ui| { ui.label(&r.details); });
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
                        if ui.button("Copy Action").clicked() {
                            ui.ctx().copy_text(r.action.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Target Object").clicked() {
                            ui.ctx().copy_text(r.target_object.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Details").clicked() {
                            ui.ctx().copy_text(r.details.clone());
                            ui.close_menu();
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
