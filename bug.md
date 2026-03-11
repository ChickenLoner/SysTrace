# Manual Testing Discovery

This file contains bugs and improvements found by manually reviewing and using the tool.

## Pending / New Findings


## Resolved

- **Process details horizontal scroll scope** — changed outer `ScrollArea::both()` to `ScrollArea::vertical()` + wrapped only the details grid in `ScrollArea::horizontal()`. Added right-click "Copy" context menu to every value label.
- **Telemetry tab column widths** — increased initial widths across all 7 panels (network, file, registry, pipes, injection, drivers, detection) so content is readable at typical window sizes without horizontal scrolling.
- **rundll32 comsvcs.dll display** — `C:windowsSystem32comsvcs.dll` and `C:templsass.dmp` have no backslashes in the original attacker command (intentional). Data is displayed correctly as-is.
- **Don't mark viewed processes** — no viewed/visited tracking exists or will be added. Process coloring is based only on: synthetic (gray), injection target (red), SYSTEM user (green), terminated (gold).
- **SYSTEM user green highlight + System integrity red** — User field shows green when process runs as SYSTEM. Integrity field shows red for "System" level, orange for "High" level.
- **Event Activity green count** — Event Activity counts > 0 now display in green to stand out.
- **Hashes split into 3 rows** — Overview tab now shows MD5, SHA256, and IMPHASH as separate rows, each with individual right-click Copy. Missing hash types show "-".
- **Remove Timeline, replace Hunt with super filter** — Bottom timeline panel removed. Hunt tab now shows a filtered process tree with checkboxes; "Generate Timeline" button opens a floating popup window with per-process swim lanes, shared time axis, zoom/pan, and event dot tooltips.
