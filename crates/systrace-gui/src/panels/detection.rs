use eframe::egui;
use egui_extras::{Column, TableBuilder};
use systrace_core::{EventDetail, EventStore, Timestamp};
use systrace_core::SharedRodeo;

use super::{cmp_ord, fmt_time, make_headers, render_empty, TabState};

// ---------------------------------------------------------------------------
// Row type
// ---------------------------------------------------------------------------

struct FindingRow {
    idx: usize,
    time: Timestamp,
    event_id: u16,
    event_type: String,
    image: String,
    computer: String,
    detail: String,
}

impl FindingRow {
    fn copy_text(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            fmt_time(self.time),
            self.event_id,
            self.event_type,
            self.image,
            self.computer,
            self.detail,
        )
    }
}

// ---------------------------------------------------------------------------
// Public render function
// ---------------------------------------------------------------------------

/// Render the Detection / query results panel.
pub fn render_detection(
    ui: &mut egui::Ui,
    event_store: &EventStore,
    query_results: &[usize],
    rodeo: &SharedRodeo,
    tab: &mut TabState,
) {
    if query_results.is_empty() {
        render_empty(ui, "No results — use the query bar above to search events.");
        return;
    }

    let mut rows: Vec<FindingRow> = query_results
        .iter()
        .copied()
        .filter_map(|idx| {
            let ev = event_store.events.get(idx)?;
            let image = ev
                .image
                .map(|s| rodeo.resolve(&s).to_owned())
                .unwrap_or_default();
            let computer = rodeo.resolve(&ev.computer).to_owned();
            let event_type = ev.event_type.display_name().to_owned();
            let detail = detail_summary(&ev.detail);
            Some(FindingRow {
                idx,
                time: ev.time_created,
                event_id: ev.event_id,
                event_type,
                image,
                computer,
                detail,
            })
        })
        .collect();

    // Sorting
    let col = tab.sort.column;
    let asc = tab.sort.ascending;
    rows.sort_by(|a, b| {
        let o = match col {
            0 => a.time.cmp(&b.time),
            1 => a.event_id.cmp(&b.event_id),
            2 => a.event_type.cmp(&b.event_type),
            3 => a.image.cmp(&b.image),
            4 => a.computer.cmp(&b.computer),
            5 => a.detail.cmp(&b.detail),
            _ => std::cmp::Ordering::Equal,
        };
        cmp_ord(o, asc)
    });

    let headers = make_headers(
        &["Time", "EventID", "Type", "Image", "Computer", "Details"],
        &tab.sort,
    );

    let row_height = 18.0_f32;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .column(Column::initial(80.0))   // Time
        .column(Column::initial(60.0))   // EventID
        .column(Column::initial(160.0))  // Type
        .column(Column::initial(200.0))  // Image
        .column(Column::initial(120.0))  // Computer
        .column(Column::remainder())     // Details
        .header(row_height, |mut header| {
            for (i, h) in headers.iter().enumerate() {
                header.col(|ui| {
                    if ui.button(h).clicked() {
                        tab.sort.toggle(i);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let ri = row.index();
                let r = &rows[ri];
                let is_selected = tab.selected_row == Some(ri);
                row.set_selected(is_selected);

                row.col(|ui| { ui.label(fmt_time(r.time)); });
                row.col(|ui| { ui.label(r.event_id.to_string()); });
                row.col(|ui| { ui.label(&r.event_type); });
                row.col(|ui| { ui.label(&r.image); });
                row.col(|ui| { ui.label(&r.computer); });
                row.col(|ui| { ui.label(&r.detail); });

                if row.response().clicked() {
                    tab.selected_row = Some(ri);
                }
                row.response().context_menu(|ui| {
                    if ui.button("Copy Row").clicked() {
                        ui.output_mut(|o| o.copied_text = r.copy_text());
                        ui.close_menu();
                    }
                    if ui.button("Copy Details").clicked() {
                        ui.output_mut(|o| o.copied_text = r.detail.clone());
                        ui.close_menu();
                    }
                });
            });
        });
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
                format!("{name} → {results}")
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
            format!("→ {target} @ {addr}")
        }
        EventDetail::ProcessAccess { target_image, granted_access, .. } => {
            let target = target_image.as_deref().unwrap_or("?");
            let access = granted_access.as_deref().unwrap_or("?");
            format!("→ {target} access={access}")
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
