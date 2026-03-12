use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, ProcessTree, Timestamp};
use systrace_core::SharedRodeo;

use super::{cmp_ord, event_color, event_label, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct TimelineRow {
    time: Timestamp,
    process_name: String,
    pid: String,
    event_id: u16,
    event_type: String,
    detail: String,
    color: egui::Color32,
}

impl TimelineRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.process_name,
            self.pid,
            self.event_id,
            self.event_type,
            self.detail,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

pub fn render_timeline_table(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    process_tree: &ProcessTree,
    rodeo: &SharedRodeo,
    event_indices: &[usize],
    tab: &mut TabState,
    filter: &str,
) {
    if event_indices.is_empty() {
        render_empty(ui, "No events. Select processes and click Generate Timeline.");
        return;
    }

    let mut rows: Vec<TimelineRow> = event_indices
        .iter()
        .copied()
        .filter_map(|idx| {
            let ev = event_store.events.get(idx)?;
            let (proc_name, pid_str) = if let Some(guid) = ev.process_guid {
                if let Some(node) = process_tree.get(&guid) {
                    (
                        node.image_name.clone().unwrap_or_else(|| "?".into()),
                        node.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    )
                } else {
                    let img = ev.image.map(|s| rodeo.resolve(&s).to_owned()).unwrap_or_else(|| "?".into());
                    let pid = ev.process_id.map(|p| p.to_string()).unwrap_or_else(|| "?".into());
                    (img, pid)
                }
            } else {
                ("?".into(), "?".into())
            };
            let event_type = event_label(ev.event_id).to_owned();
            let detail = detail_summary(&ev.detail);
            let color = event_color(ev.event_id);
            Some(TimelineRow {
                time: ev.time_created,
                process_name: proc_name,
                pid: pid_str,
                event_id: ev.event_id,
                event_type,
                detail,
                color,
            })
        })
        .collect();

    if !filter.is_empty() {
        let f = filter.to_lowercase();
        rows.retain(|r| r.copy_text().to_lowercase().contains(&f));
    }
    if rows.is_empty() {
        render_empty(ui, "No matching events.");
        return;
    }

    // Sort
    let col = tab.sort.column;
    let asc = tab.sort.ascending;
    rows.sort_by(|a, b| {
        let o = match col {
            0 => a.time.cmp(&b.time),
            1 => a.process_name.cmp(&b.process_name),
            2 => a.pid.cmp(&b.pid),
            3 => a.event_id.cmp(&b.event_id),
            4 => a.event_type.cmp(&b.event_type),
            5 => a.detail.cmp(&b.detail),
            _ => std::cmp::Ordering::Equal,
        };
        cmp_ord(o, asc)
    });

    let headers = make_headers(
        &["Time", "Process", "PID", "EventID", "Type", "Details"],
        &tab.sort,
    );

    let mut next_sort: Option<usize> = None;
    let mut next_selected = tab.selected_row;
    let selected = tab.selected_row;
    let rows_ref = &rows;

    egui::ScrollArea::horizontal().auto_shrink([false, false]).show(ui, |ui| {
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(185.0).clip(true))  // Time
            .column(Column::initial(140.0).clip(true))   // Process
            .column(Column::initial(60.0).clip(true))    // PID
            .column(Column::initial(65.0).clip(true))    // EventID
            .column(Column::initial(150.0).clip(true))   // Type
            .column(Column::remainder().clip(true).at_least(200.0)) // Details
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
                    row.col(|ui| { ui.label(&r.process_name); });
                    row.col(|ui| { ui.label(&r.pid); });
                    row.col(|ui| {
                        ui.colored_label(r.color, r.event_id.to_string());
                    });
                    row.col(|ui| {
                        ui.colored_label(r.color, &r.event_type);
                    });
                    row.col(|ui| { ui.label(&r.detail); });
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
                        if ui.button("Copy Process").clicked() {
                            ui.ctx().copy_text(r.process_name.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy Details").clicked() {
                            ui.ctx().copy_text(r.detail.clone());
                            ui.close_menu();
                        }
                    });
                });
            });
    });

    if let Some(c) = next_sort {
        tab.sort.toggle(c);
    }
    tab.selected_row = next_selected;
}

// ---------------------------------------------------------------------------
// Build a short summary string from EventDetail
// ---------------------------------------------------------------------------

fn detail_summary(detail: &EventDetail) -> String {
    match detail {
        EventDetail::ProcessCreate { command_line, .. } => {
            command_line.as_deref().unwrap_or("-").to_owned()
        }
        EventDetail::NetworkConnect {
            destination_ip,
            destination_port,
            destination_hostname,
            protocol,
            ..
        } => {
            let ip = destination_ip.as_deref().unwrap_or("?");
            let port = destination_port.map(|p| p.to_string()).unwrap_or_else(|| "?".to_owned());
            let host = destination_hostname.as_deref().unwrap_or("");
            let proto = protocol.as_deref().unwrap_or("");
            if host.is_empty() {
                format!("{proto} {ip}:{port}")
            } else {
                format!("{proto} {host} ({ip}:{port})")
            }
        }
        EventDetail::DnsQuery { query_name, query_results, .. } => {
            let name = query_name.as_deref().unwrap_or("?");
            let results = query_results.as_deref().unwrap_or("");
            if results.is_empty() {
                name.to_owned()
            } else {
                format!("{name} -> {results}")
            }
        }
        EventDetail::FileCreate { target_filename, .. } => {
            target_filename.as_deref().unwrap_or("-").to_owned()
        }
        EventDetail::RegistryEvent { target_object, details, event_type, .. } => {
            let action = event_type.as_deref().unwrap_or("?");
            let obj = target_object.as_deref().unwrap_or("?");
            let det = details.as_deref().unwrap_or("");
            if det.is_empty() {
                format!("{action} {obj}")
            } else {
                format!("{action} {obj} = {det}")
            }
        }
        EventDetail::PipeEvent { event_type, pipe_name } => {
            let name = pipe_name.as_deref().unwrap_or("?");
            format!("{event_type} {name}")
        }
        EventDetail::CreateRemoteThread { target_image, start_address, .. } => {
            let target = target_image.as_deref().unwrap_or("?");
            let addr = start_address.as_deref().unwrap_or("?");
            format!("-> {target} @ {addr}")
        }
        EventDetail::ProcessAccess { target_image, granted_access, .. } => {
            let target = target_image.as_deref().unwrap_or("?");
            let access = granted_access.as_deref().unwrap_or("?");
            format!("-> {target} access={access}")
        }
        EventDetail::FileDeleteEvent { target_filename, .. } => {
            target_filename.as_deref().unwrap_or("-").to_owned()
        }
        EventDetail::DriverLoad { image_loaded, signature_status, .. } => {
            let img = image_loaded.as_deref().unwrap_or("?");
            let sig = signature_status.as_deref().unwrap_or("");
            if sig.is_empty() { img.to_owned() } else { format!("{img} [{sig}]") }
        }
        EventDetail::ImageLoad { image_loaded, signature_status, .. } => {
            let img = image_loaded.as_deref().unwrap_or("?");
            let sig = signature_status.as_deref().unwrap_or("");
            if sig.is_empty() { img.to_owned() } else { format!("{img} [{sig}]") }
        }
        EventDetail::FileCreateStreamHash { target_filename, .. } => {
            target_filename.as_deref().unwrap_or("-").to_owned()
        }
        EventDetail::ProcessTampering { tampering_type } => {
            tampering_type.as_deref().unwrap_or("?").to_owned()
        }
        EventDetail::SysmonConfigChange { configuration, .. } => {
            configuration.as_deref().unwrap_or("?").to_owned()
        }
        EventDetail::RawAccessRead { device } => {
            device.as_deref().unwrap_or("?").to_owned()
        }
        EventDetail::ClipboardChange { hashes, .. } => {
            hashes.as_deref().unwrap_or("").to_owned()
        }
        EventDetail::ProcessTerminate => String::new(),
        EventDetail::FileCreateTime { target_filename, .. } => {
            target_filename.as_deref().unwrap_or("-").to_owned()
        }
        EventDetail::WmiActivity { event_type, operation, .. } => {
            let op = operation.as_deref().unwrap_or("");
            if op.is_empty() { event_type.clone() } else { format!("{event_type}: {op}") }
        }
        EventDetail::Generic { fields } => {
            fields.iter().take(3).map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
        }
    }
}
