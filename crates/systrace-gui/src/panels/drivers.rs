use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct DriverRow {
    time: Timestamp,
    kind: &'static str, // "Driver" or "Image"
    image_loaded: String,
    signature: String,
    signature_status: String,
    mitre: String,
}

impl DriverRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.kind,
            self.image_loaded,
            self.signature,
            self.signature_status,
            self.mitre,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_drivers(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let indices = event_store.events_for_process_and_types(&guid, &[6, 7]);
    if indices.is_empty() {
        render_empty(ui, "No driver/module load events for this process.");
        return;
    }

    let mut rows: Vec<DriverRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            match &ev.detail {
                EventDetail::DriverLoad { image_loaded, signature, signature_status, .. } => {
                    Some(DriverRow {
                        time: ev.time_created,
                        kind: "Driver",
                        image_loaded: image_loaded.clone().unwrap_or_default(),
                        signature: signature.clone().unwrap_or_default(),
                        signature_status: signature_status.clone().unwrap_or_default(),
                        mitre: ev.mitre_technique.as_ref().map(|m| m.id.clone()).unwrap_or_default(),
                    })
                }
                EventDetail::ImageLoad { image_loaded, signature, signature_status, .. } => {
                    Some(DriverRow {
                        time: ev.time_created,
                        kind: "Image",
                        image_loaded: image_loaded.clone().unwrap_or_default(),
                        signature: signature.clone().unwrap_or_default(),
                        signature_status: signature_status.clone().unwrap_or_default(),
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
        1 => rows.sort_by(|a, b| cmp_ord(a.kind.cmp(b.kind), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.image_loaded.cmp(&b.image_loaded), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.signature.cmp(&b.signature), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.signature_status.cmp(&b.signature_status), sort_asc)),
        5 => rows.sort_by(|a, b| cmp_ord(a.mitre.cmp(&b.mitre), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(
        &["Time", "Type", "Image Loaded", "Signature", "Status", "MITRE"],
        &tab.sort,
    );

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))  // Time
            .column(Column::initial(75.0).clip(true))   // Action
            .column(Column::initial(320.0).clip(true))  // Image Loaded
            .column(Column::initial(180.0).clip(true))  // Signature
            .column(Column::initial(120.0).clip(true))  // Status
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
                    row.col(|ui| { ui.label(r.kind); });
                    row.col(|ui| { ui.label(&r.image_loaded); });
                    row.col(|ui| { ui.label(&r.signature); });
                    row.col(|ui| { ui.label(&r.signature_status); });
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
                        if ui.button("Copy Image Loaded").clicked() {
                            ui.ctx().copy_text(r.image_loaded.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Signature").clicked() {
                            ui.ctx().copy_text(r.signature.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Status").clicked() {
                            ui.ctx().copy_text(r.signature_status.clone());
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
