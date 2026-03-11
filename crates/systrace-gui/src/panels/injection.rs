use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct InjectionRow {
    time: Timestamp,
    kind: &'static str,    // "RemoteThread", "ProcessAccess", "Tampering"
    role: &'static str,    // "Source", "Target", or "-"
    source: String,
    target: String,
    details: String,
}

impl InjectionRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.kind,
            self.role,
            self.source,
            self.target,
            self.details,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_injection(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    // Merge: events where this process is source (8, 10, 25 in its own index)
    // + events where this process is the target (8, 10 only, from target index).
    let mut all_indices: Vec<usize> = event_store
        .events_for_process_and_types(&guid, &[8, 10, 25])
        .into_iter()
        .chain(event_store.events_targeting_process(&guid).iter().copied())
        .collect();

    all_indices.sort_unstable();
    all_indices.dedup();

    if all_indices.is_empty() {
        render_empty(ui, "No injection events for this process.");
        return;
    }

    let mut rows: Vec<InjectionRow> = all_indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            match &ev.detail {
                EventDetail::CreateRemoteThread {
                    source_process_guid,
                    source_image,
                    target_process_guid,
                    target_image,
                    start_module,
                    start_function,
                    ..
                } => {
                    let role = if source_process_guid.as_ref() == Some(&guid) {
                        "Source"
                    } else if target_process_guid.as_ref() == Some(&guid) {
                        "Target"
                    } else {
                        "-"
                    };
                    let details = match (start_module.as_deref(), start_function.as_deref()) {
                        (Some(m), Some(f)) => format!("{}!{}", m, f),
                        (Some(m), None) => m.to_owned(),
                        (None, Some(f)) => f.to_owned(),
                        _ => String::new(),
                    };
                    Some(InjectionRow {
                        time: ev.time_created,
                        kind: "RemoteThread",
                        role,
                        source: source_image.clone().unwrap_or_default(),
                        target: target_image.clone().unwrap_or_default(),
                        details,
                    })
                }
                EventDetail::ProcessAccess {
                    source_process_guid,
                    source_image,
                    target_process_guid,
                    target_image,
                    granted_access,
                    ..
                } => {
                    let role = if source_process_guid.as_ref() == Some(&guid) {
                        "Source"
                    } else if target_process_guid.as_ref() == Some(&guid) {
                        "Target"
                    } else {
                        "-"
                    };
                    Some(InjectionRow {
                        time: ev.time_created,
                        kind: "ProcessAccess",
                        role,
                        source: source_image.clone().unwrap_or_default(),
                        target: target_image.clone().unwrap_or_default(),
                        details: granted_access.clone().unwrap_or_default(),
                    })
                }
                EventDetail::ProcessTampering { tampering_type } => Some(InjectionRow {
                    time: ev.time_created,
                    kind: "Tampering",
                    role: "-",
                    source: String::new(),
                    target: String::new(),
                    details: tampering_type.clone().unwrap_or_default(),
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
        1 => rows.sort_by(|a, b| cmp_ord(a.kind.cmp(b.kind), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.role.cmp(b.role), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.source.cmp(&b.source), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.target.cmp(&b.target), sort_asc)),
        5 => rows.sort_by(|a, b| cmp_ord(a.details.cmp(&b.details), sort_asc)),
        _ => {}
    }

    let selected = tab.selected_row;
    let headers = make_headers(
        &["Time", "Type", "Role", "Source", "Target", "Details"],
        &tab.sort,
    );

    let mut next_sort: Option<usize> = None;
    let mut next_selected = selected;
    let rows_ref = &rows;

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .sense(egui::Sense::click())
        .column(Column::initial(90.0).clip(true))
        .column(Column::initial(110.0).clip(true))
        .column(Column::initial(65.0).clip(true))
        .column(Column::initial(200.0).clip(true))
        .column(Column::initial(200.0).clip(true))
        .column(Column::remainder().clip(true))
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
                row.col(|ui| { ui.label(r.role); });
                row.col(|ui| { ui.label(&r.source); });
                row.col(|ui| { ui.label(&r.target); });
                row.col(|ui| { ui.label(&r.details); });
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
