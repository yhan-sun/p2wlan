const p2wlanAppName = 'P2WLAN';

/// Page width policy (desktop). Content is centered and capped per page so
/// wide windows never stretch a single page to the full viewport, while
/// 1440/1600/1920 screens do not collapse to a narrow centered column.
const dashboardPageMaxWidth = 1200.0;

/// Devices page master/detail (List + Inspector) content threshold.
///
/// This is a page-specific content threshold, not a shell window-size class:
/// inside the expanded desktop shell the page content is the window width
/// minus the compact desktop sidebar, its divider, and page padding. The
/// shell sidebar is intentionally 184px, so keep a little breathing room
/// before turning the Devices page into a two-pane inspector. This preserves
/// the dialog presentation around 1200px while 1280px still gets the desktop
/// list + inspector layout.
const nodesInspectorMinWidth = 1000.0;
const nodesPageMaxWidth = 1360.0;
const diagnosticsPageMaxWidth = 1120.0;
const settingsPageMaxWidth = 960.0;
