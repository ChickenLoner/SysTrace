use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct PipeRow {
    time: Timestamp,
    action: String,
    pipe_name: String,
}

impl PipeRow {
    fn copy_text(&self) -> String {
        format!("{}\t{}\t{}", fmt_time(self.time), self.action, self.pipe_name)
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_pipes(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let indices = event_store.events_for_process_and_types(&guid, &[17, 18]);
    if indices.is_empty() {
        render_empty(ui, "No pipe events for this process.");
        return;
    }

    let mut rows: Vec<PipeRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            if let EventDetail::PipeEvent { event_type, pipe_name } = &ev.detail {
                let action = match event_type.as_str() {
                    "CreatePipe" => "Create".to_owned(),
                    "ConnectPipe" => "Connect".to_owned(),
                    other => other.to_owned(),
                };
                Some(PipeRow {
                    time: ev.time_created,
                    action,
                    pipe_name: pipe_name.clone().unwrap_or_default(),
                })
            } else {
                None
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
        2 => rows.sort_by(|a, b| cmp_ord(a.pipe_name.cmp(&b.pipe_name), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(&["Time", "Action", "Pipe Name"], &tab.sort);

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))  // Time
            .column(Column::initial(100.0).clip(true))  // Action
            .column(Column::remainder().clip(true).at_least(200.0)) // Pipe Name
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
                    row.col(|ui| { ui.label(&r.pipe_name); });
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
                        if ui.button("Copy Pipe Name").clicked() {
                            ui.ctx().copy_text(r.pipe_name.clone());
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
