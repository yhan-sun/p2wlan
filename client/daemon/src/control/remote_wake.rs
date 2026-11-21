//! Device-authenticated Wake-on-LAN runs alongside control registration.
//! It never reads or writes the ordinary signaling queue.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use p2pnet_netbind::wake::{list_lan_interfaces, send_magic_packet_excluding, MacAddress};
use serde::Serialize;
use tokio::sync::watch;
use tokio::time::{sleep, timeout_at, Instant};

use crate::config::{Config, WakeConfig};

use super::{control_shutdown_requested, CriticalControlAuth, RouteAwareControlHttpClient};
use http::{WakeClaim, WakeHttp, WakeHttpError};

mod http;

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
const TARGET_REFRESH: Duration = Duration::from_secs(60);
const LOCAL_SEND_LIMIT: usize = 8;
const LOCAL_SEND_WINDOW: Duration = Duration::from_secs(60);
const MAC_SEND_WINDOW: Duration = Duration::from_secs(5);
const COMPLETION_LIMIT: usize = 32;
const COMPLETION_TTL: Duration = Duration::from_secs(30);

const TARGET_PLATFORM: bool = cfg!(target_os = "windows");
const PROXY_PLATFORM: bool = cfg!(any(
    target_os = "windows",
    target_os = "macos",
    all(target_os = "linux", not(target_env = "ohos")),
));

fn permitted_control_transport(base_url: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(base_url) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        }),
        _ => false,
    }
}

pub(super) fn request_proxy_capability(config: &Config, base_url: &str) -> bool {
    config.wake.proxy
        && PROXY_PLATFORM
        && !config.network.manual
        && !config.control.device_credential.trim().is_empty()
        && permitted_control_transport(base_url)
}

pub(super) fn enabled(config: &Config, base_url: &str) -> bool {
    // Windows needs one authenticated DELETE per registration when opted out
    // so a previous, persisted target is withdrawn after changing the setting.
    (TARGET_PLATFORM || (PROXY_PLATFORM && config.wake.proxy))
        && permitted_control_transport(base_url)
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State {
    Disabled,
    UnsupportedPlatform,
    RegistrationPending,
    NoControlCredential,
    InsecureControl,
    UnsupportedControl,
    ControlUnavailable,
    WithdrawalPending,
    Active,
    Advertised,
    NoLanInterface,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) struct WakeStatusSnapshot {
    proxy: bool,
    allow_remote: bool,
    proxy_state: State,
    target_state: State,
}

/// Shared only for privacy-safe local diagnostics. No job, token, interface
/// name, MAC or network address enters the snapshot.
pub(crate) struct WakeStatus(Mutex<WakeStatusSnapshot>);

impl Default for WakeStatus {
    fn default() -> Self {
        Self(Mutex::new(WakeStatusSnapshot {
            proxy: false,
            allow_remote: false,
            proxy_state: State::Disabled,
            target_state: State::Disabled,
        }))
    }
}

impl WakeStatus {
    pub(super) fn new(config: &Config, runtime_enabled: bool) -> Self {
        let base_url = super::normalize_http_base_url(&config.control.server_url);
        let initial_state = if config.network.manual {
            State::Disabled
        } else if !runtime_enabled {
            State::NoControlCredential
        } else if !permitted_control_transport(&base_url) {
            State::InsecureControl
        } else {
            State::RegistrationPending
        };
        Self(Mutex::new(WakeStatusSnapshot {
            proxy: config.wake.proxy,
            allow_remote: config.wake.allow_remote,
            proxy_state: role_state(config.wake.proxy, PROXY_PLATFORM, initial_state),
            target_state: role_state(config.wake.allow_remote, TARGET_PLATFORM, initial_state),
        }))
    }

    pub(crate) fn snapshot(&self) -> WakeStatusSnapshot {
        *self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn set_proxy(&self, state: State) {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .proxy_state = state;
    }

    fn set_target(&self, state: State) {
        self.0
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .target_state = state;
    }

    fn reset(&self, settings: &WakeConfig, state: State) {
        let mut status = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        status.proxy_state = role_state(settings.proxy, PROXY_PLATFORM, state);
        status.target_state = role_state(settings.allow_remote, TARGET_PLATFORM, state);
    }
}

fn role_state(configured: bool, platform: bool, state: State) -> State {
    match (configured, platform) {
        (false, _) => State::Disabled,
        (true, false) => State::UnsupportedPlatform,
        (true, true) => state,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WakeResult {
    Sent,
    Failed(&'static str),
}

impl WakeResult {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::Sent => ("sent", ""),
            Self::Failed(reason) => ("failed", reason),
        }
    }
}

#[derive(Default)]
struct Agent {
    sent: VecDeque<(Instant, MacAddress)>,
    finished: VecDeque<(Instant, String, WakeResult)>,
}

impl Agent {
    fn allow(&mut self, now: Instant, mac: MacAddress) -> bool {
        self.sent
            .retain(|(at, _)| now.duration_since(*at) < LOCAL_SEND_WINDOW);
        if self.sent.len() >= LOCAL_SEND_LIMIT
            || self
                .sent
                .iter()
                .any(|(at, previous)| *previous == mac && now.duration_since(*at) < MAC_SEND_WINDOW)
        {
            return false;
        }
        self.sent.push_back((now, mac));
        true
    }

    fn finished(&mut self, job_id: &str, now: Instant) -> Option<WakeResult> {
        self.finished
            .retain(|(at, _, _)| now.duration_since(*at) < COMPLETION_TTL);
        self.finished
            .iter()
            .find(|(_, id, _)| id == job_id)
            .map(|(_, _, result)| *result)
    }

    fn record(&mut self, now: Instant, job_id: &str, result: WakeResult) {
        if self.finished.len() == COMPLETION_LIMIT {
            self.finished.pop_front();
        }
        self.finished.push_back((now, job_id.into(), result));
    }

    async fn send(&mut self, claim: &WakeClaim, interface: Option<&str>, tun: &str) -> WakeResult {
        let Ok(mac) = claim.mac.parse::<MacAddress>() else {
            return WakeResult::Failed("target_no_mac");
        };
        let now = Instant::now();
        if now >= claim.deadline {
            return WakeResult::Failed("expired");
        }
        if !self.allow(now, mac) {
            return WakeResult::Failed("rate_limited");
        }

        match timeout_at(
            claim.deadline,
            send_magic_packet_excluding(mac, interface, tun),
        )
        .await
        {
            Ok(Ok(())) => WakeResult::Sent,
            Ok(Err(error)) => WakeResult::Failed(error.reason()),
            Err(_) => WakeResult::Failed("expired"),
        }
    }

    async fn poll(
        &mut self,
        client: &WakeHttp<'_>,
        interface: Option<&str>,
        tun: &str,
        is_current: impl Fn() -> bool,
    ) -> Result<(), WakeHttpError> {
        for id in client.jobs().await? {
            if !is_current() {
                return Ok(());
            }
            let Some(claim) = client.claim(&id).await? else {
                continue;
            };
            if !is_current() {
                return Ok(());
            }
            let result = match self.finished(&id, Instant::now()) {
                Some(result) => result,
                None => {
                    let result = self.send(&claim, interface, tun).await;
                    self.record(Instant::now(), &id, result);
                    result
                }
            };
            if is_current() && Instant::now() < claim.deadline {
                client.result(&id, &claim, result).await?;
            }
        }
        Ok(())
    }
}

async fn sync_target(
    client: &WakeHttp<'_>,
    allow_remote: bool,
    tun: &str,
) -> Result<State, WakeHttpError> {
    if !allow_remote {
        client.delete_target().await?;
        return Ok(State::Disabled);
    }
    let tun = tun.to_owned();
    let wired = tokio::task::spawn_blocking(move || {
        let mut interfaces = list_lan_interfaces()?;
        interfaces.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        Ok::<_, std::io::Error>(
            interfaces
                .into_iter()
                .find(|entry| entry.wired && !entry.name.eq_ignore_ascii_case(&tun)),
        )
    })
    .await
    .map_err(|_| WakeHttpError::Unavailable)?
    .map_err(|_| WakeHttpError::Unavailable)?;

    match wired {
        Some(wired) => {
            client.put_target(wired.mac, &wired.name).await?;
            Ok(State::Advertised)
        }
        // A temporarily down adapter must not withdraw the last explicitly
        // advertised target, especially while Windows is powering down.
        None => Ok(State::NoLanInterface),
    }
}

pub(super) struct Profile {
    settings: WakeConfig,
    tunnel_interface: String,
    proxy_activation: Option<serde_json::Value>,
}

impl Profile {
    pub(super) fn new(config: &Config) -> Self {
        let incarnation = crate::incarnation::local_incarnation();
        Self {
            settings: config.wake.clone(),
            tunnel_interface: config.network.interface.clone(),
            proxy_activation: (config.wake.proxy && PROXY_PLATFORM && incarnation != 0)
                .then(|| super::http::registration_payload(config, incarnation, true)),
        }
    }
}

struct RegistrationWorker<'a> {
    profile: &'a Profile,
    auth_rx: &'a watch::Receiver<Option<CriticalControlAuth>>,
    agent: &'a mut Agent,
    status: &'a WakeStatus,
    pool: &'a RouteAwareControlHttpClient,
}

impl RegistrationWorker<'_> {
    async fn run(&mut self, auth: CriticalControlAuth) {
        if !auth.wake_device_credential {
            self.status
                .reset(&self.profile.settings, State::NoControlCredential);
            return;
        }
        let Some(seq) = auth.registration_seq.filter(|seq| *seq > 0) else {
            self.status
                .reset(&self.profile.settings, State::UnsupportedControl);
            return;
        };

        let mut proxy = self.profile.settings.proxy && PROXY_PLATFORM;
        let mut proxy_accepted = auth.wake_proxy_v1;
        let mut target = TARGET_PLATFORM;
        if target && !self.profile.settings.allow_remote {
            self.status.set_target(State::WithdrawalPending);
        }
        let mut target_due = Instant::now();
        let mut target_backoff = POLL_INTERVAL;
        let mut proxy_backoff = POLL_INTERVAL;
        while proxy || target {
            let Some((http, pool_id)) = self.pool.remote_wake_pool() else {
                self.status
                    .reset(&self.profile.settings, State::ControlUnavailable);
                sleep(POLL_INTERVAL).await;
                continue;
            };
            let client = WakeHttp::new(&http, &auth, seq);
            // A changed route/pool supersedes all requests and any LAN send
            // in this round. Neither async branch holds a shared lock.
            let delay = tokio::select! {
                biased;
                _ = self.pool.remote_wake_pool_changed(pool_id) => continue,
                delay = async {
                    if target && Instant::now() >= target_due {
                        match sync_target(&client, self.profile.settings.allow_remote, &self.profile.tunnel_interface).await {
                            Ok(state) => {
                                self.status.set_target(state);
                                target = self.profile.settings.allow_remote;
                                target_backoff = POLL_INTERVAL;
                                let interval = if state == State::NoLanInterface { POLL_INTERVAL } else { TARGET_REFRESH };
                                target_due = Instant::now() + interval;
                            }
                            Err(WakeHttpError::Unsupported) => {
                                self.status.set_target(if self.profile.settings.allow_remote {
                                    State::UnsupportedControl
                                } else {
                                    State::Disabled
                                });
                                target = false;
                            }
                            Err(_) => {
                                self.status.set_target(State::ControlUnavailable);
                                target_due = Instant::now() + target_backoff;
                                target_backoff = (target_backoff * 2).min(MAX_BACKOFF);
                            }
                        }
                    }
                    if !proxy {
                        return target_due.saturating_duration_since(Instant::now());
                    }
                    // A user-JWT bootstrap may just have issued this device
                    // credential. Attest the same boot through the scoped
                    // worker; a wake-only outage cannot delay the data plane.
                    if !proxy_accepted {
                        let accepted = match &self.profile.proxy_activation {
                            Some(payload) => client.activate_proxy(payload).await,
                            None => Ok(false),
                        };
                        match accepted {
                            Ok(true) => proxy_accepted = true,
                            Ok(false) | Err(WakeHttpError::Unsupported) => {
                                self.status.set_proxy(State::UnsupportedControl);
                                proxy = false;
                                return target_due.saturating_duration_since(Instant::now());
                            }
                            Err(_) => {
                                self.status.set_proxy(State::ControlUnavailable);
                                let delay = proxy_backoff;
                                proxy_backoff = (proxy_backoff * 2).min(MAX_BACKOFF);
                                return delay;
                            }
                        }
                    }
                    let current = || {
                        matches!(self.auth_rx.has_changed(), Ok(false))
                            && self.pool.remote_wake_pool_is_current(pool_id)
                    };
                    match self.agent.poll(
                        &client,
                        self.profile.settings.proxy_interface.as_deref(),
                        &self.profile.tunnel_interface,
                        current,
                    ).await {
                        Ok(()) => {
                            self.status.set_proxy(State::Active);
                            proxy_backoff = POLL_INTERVAL;
                        }
                        Err(WakeHttpError::Unsupported) => {
                            self.status.set_proxy(State::UnsupportedControl);
                            proxy = false;
                        }
                        Err(_) => {
                            self.status.set_proxy(State::ControlUnavailable);
                            let delay = proxy_backoff;
                            proxy_backoff = (proxy_backoff * 2).min(MAX_BACKOFF);
                            return delay;
                        }
                    }
                    POLL_INTERVAL
                } => delay,
            };
            if proxy || target {
                sleep(delay).await;
            }
        }
    }
}

pub(super) async fn run(
    profile: Profile,
    status: Arc<WakeStatus>,
    pool: RouteAwareControlHttpClient,
    mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut agent = Agent::default();
    loop {
        status.reset(&profile.settings, State::RegistrationPending);
        let auth = auth_rx.borrow_and_update().clone();
        let auth_guard = auth_rx.clone();
        let work = async {
            if let Some(auth) = auth {
                RegistrationWorker {
                    profile: &profile,
                    auth_rx: &auth_guard,
                    agent: &mut agent,
                    status: &status,
                    pool: &pool,
                }
                .run(auth)
                .await;
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            biased;
            _ = control_shutdown_requested(&mut shutdown) => break,
            update = auth_rx.changed() => {
                if update.is_err() {
                    break;
                }
            }
            _ = work => {}
        };
    }
    status.reset(&profile.settings, State::Disabled);
}

#[cfg(test)]
mod tests;
