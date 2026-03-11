use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessGuid, Timestamp};

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct NetworkRow {
    time: Timestamp,
    direction: &'static str,
    protocol: String,
    source: String,
    destination: String,
    hostname: String,
    extra: String, // DNS query status or empty
}

impl NetworkRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.direction,
            self.protocol,
            self.source,
            self.destination,
            self.hostname,
            self.extra,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_network(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    guid: ProcessGuid,
    tab: &mut TabState,
    filter: &str,
    time_range: Option<(Timestamp, Timestamp)>,
) {
    let indices = event_store.events_for_process_and_types(&guid, &[3, 22]);
    if indices.is_empty() {
        render_empty(ui, "No network events for this process.");
        return;
    }

    // Build typed rows
    let mut rows: Vec<NetworkRow> = indices
        .iter()
        .filter_map(|&i| {
            let ev = &event_store.events[i];
            match &ev.detail {
                EventDetail::NetworkConnect {
                    initiated,
                    protocol,
                    source_ip,
                    source_port,
                    destination_ip,
                    destination_port,
                    destination_hostname,
                    ..
                } => {
                    let direction = match initiated {
                        Some(true) => "Outbound",
                        Some(false) => "Inbound",
                        None => "?",
                    };
                    let src = format!(
                        "{}:{}",
                        source_ip.as_deref().unwrap_or("-"),
                        source_port.map(|p| p.to_string()).unwrap_or_default()
                    );
                    let dst = format!(
                        "{}:{}",
                        destination_ip.as_deref().unwrap_or("-"),
                        destination_port.map(|p| p.to_string()).unwrap_or_default()
                    );
                    Some(NetworkRow {
                        time: ev.time_created,
                        direction,
                        protocol: protocol.clone().unwrap_or_default(),
                        source: src,
                        destination: dst,
                        hostname: destination_hostname.clone().unwrap_or_default(),
                        extra: String::new(),
                    })
                }
                EventDetail::DnsQuery { query_name, query_status, query_results } => {
                    Some(NetworkRow {
                        time: ev.time_created,
                        direction: "DNS",
                        protocol: "DNS".to_owned(),
                        source: "-".to_owned(),
                        destination: query_results.clone().unwrap_or_default(),
                        hostname: query_name.clone().unwrap_or_default(),
                        extra: query_status.clone().unwrap_or_default(),
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

    // Sort rows according to current sort state
    let sort_col = tab.sort.column;
    let sort_asc = tab.sort.ascending;
    match sort_col {
        0 => rows.sort_by(|a, b| cmp_ord(a.time.cmp(&b.time), sort_asc)),
        1 => rows.sort_by(|a, b| cmp_ord(a.direction.cmp(b.direction), sort_asc)),
        2 => rows.sort_by(|a, b| cmp_ord(a.protocol.cmp(&b.protocol), sort_asc)),
        3 => rows.sort_by(|a, b| cmp_ord(a.source.cmp(&b.source), sort_asc)),
        4 => rows.sort_by(|a, b| cmp_ord(a.destination.cmp(&b.destination), sort_asc)),
        5 => rows.sort_by(|a, b| cmp_ord(a.hostname.cmp(&b.hostname), sort_asc)),
        _ => {}
    }

    // Snapshot Copy values for closures
    let selected = tab.selected_row;
    let headers = make_headers(
        &["Time", "Direction", "Protocol", "Source", "Destination", "Hostname"],
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
        .column(Column::initial(75.0).clip(true))
        .column(Column::initial(55.0).clip(true))
        .column(Column::initial(135.0).clip(true))
        .column(Column::initial(135.0).clip(true))
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
                row.col(|ui| { ui.label(r.direction); });
                row.col(|ui| { ui.label(&r.protocol); });
                row.col(|ui| { ui.label(&r.source); });
                row.col(|ui| { ui.label(&r.destination); });
                row.col(|ui| { ui.label(&r.hostname); });
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

