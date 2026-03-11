use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct FileRow {
    time: Timestamp,
    action: &'static str,
    filename: String,
    hashes: String,
}

impl FileRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.action,
            self.filename,
            self.hashes,
        )
    }
}

fn action_for_id(event_id: u16) -> &'static str {
    match event_id {
        11 => "Create",
        15 => "ADS Stream",
        23 => "Delete",
        26 => "Delete Detected",
        27 => "Block Exec",
        28 => "Block Shred",
        29 => "Exec Detected",
        _  => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_file_activity(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let indices = event_store.events_for_process_and_types(&guid, &[11, 15, 23, 26, 27, 28, 29]);
    if indices.is_empty() {
        render_empty(ui, "No file activity events for this process.");
        return;
    }

    let mut rows: Vec<FileRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            let action = action_for_id(ev.event_id);
            match &ev.detail {
                EventDetail::FileCreate { target_filename, .. } => Some(FileRow {
                    time: ev.time_created,
                    action,
                    filename: target_filename.clone().unwrap_or_default(),
                    hashes: String::new(),
                }),
                EventDetail::FileCreateStreamHash { target_filename, hash, .. } => Some(FileRow {
                    time: ev.time_created,
                    action,
                    filename: target_filename.clone().unwrap_or_default(),
                    hashes: hash.clone().unwrap_or_default(),
                }),
                EventDetail::FileDeleteEvent { target_filename, hashes, .. } => Some(FileRow {
                    time: ev.time_created,
                    action,
                    filename: target_filename.clone().unwrap_or_default(),
                    hashes: hashes.clone().unwrap_or_default(),
                }),
                EventDetail::FileCreateTime { target_filename, .. } => Some(FileRow {
                    time: ev.time_created,
                    action: "Timestomp",
                    filename: target_filename.clone().unwrap_or_default(),
                    hashes: String::new(),
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
        render_empty(ui, "No matching events.");
        return;
    }

    let sort_col = tab.sort.column;
    let sort_asc = tab.sort.ascending;
    match sort_col {
        0 => rows.sort_by(|a, b| cmp_ord(a.time.cmp(&b.time), sort_asc)),
        1 => rows.sort_by(|a, b| cmp_ord(a.action.cmp(b.action), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.filename.cmp(&b.filename), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.hashes.cmp(&b.hashes), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(&["Time", "Action", "Target Filename", "Hashes"], &tab.sort);

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .sense(egui::Sense::click())
        .column(Column::initial(90.0).clip(true))
        .column(Column::initial(105.0).clip(true))
        .column(Column::remainder().clip(true))
        .column(Column::initial(180.0).clip(true))
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
                row.col(|ui| { ui.label(r.action); });
                row.col(|ui| { ui.label(&r.filename); });
                row.col(|ui| { ui.label(&r.hashes); });
                let resp = row.response();
                if resp.clicked() {
                    next_selected = Some(i);
                }
                let copy = r.copy_text();
                resp.context_menu(|ui| {
                    if ui.button("Copy row").clicked() {
                        ui.ctx().copy_text(copy.clone());
                        ui.close_menu();
                    }
                });
            });
        });

    if let Some(col) = next_sort {
        tab.sort.toggle(col);
    }
    tab.selected_row = next_selected;
}
