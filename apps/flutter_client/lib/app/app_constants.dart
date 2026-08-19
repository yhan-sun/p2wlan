const p2wlanAppName = 'P2WLAN';

/// Page width policy (desktop). Content is centered and capped per page so
/// wide windows never stretch a single page to the full viewport, while
/// 1440/1600/1920 screens do not collapse to a narrow centered column.
const dashboardPageMaxWidth = 1200.0;

/// Devices page master/detail (List + Inspector) content threshold.
///
/// This is a page-specific content threshold, not a shell window-size class:
/// inside the expanded desktop shell the page content is the window width
/// minus the sidebar (216px), the rail divider, and the page padding
/// (24px each side). A full 1280px window leaves roughly 1015px of content,
/// which comfortably fits a ~600px list and a ~400px inspector, while a
/// 1200px window leaves only ~935px, which is too narrow to force the
/// inspector in — those windows keep the medium List + Dialog presentation.
const nodesInspectorMinWidth = 960.0;
const nodesPageMaxWidth = 1360.0;
const tunnelsPageMaxWidth = 1100.0;
const diagnosticsPageMaxWidth = 1120.0;
const settingsPageMaxWidth = 960.0;
