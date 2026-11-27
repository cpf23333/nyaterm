//! One-shot Windows Native (ActiveX) RDP authentication probe used by the
//! connection editor's "test connection" action.
//!
//! The system control is thread-affine: it must be created on a thread whose
//! message queue is pumped, and its parent window must belong to that same
//! thread. The probe therefore owns a short-lived STA thread with a hidden
//! parent window, drives the staged [`NativeRdpControl`] exactly like the
//! application does, and reports the first terminal outcome. It never creates a
//! tab and never presents a window.
//!
//! Certificate handling matches the other probes: every policy is narrowed to
//! [`RdpCertificatePolicy::Insecure`] for this single attempt, so a system
//! prompt can never block an unattended test. The real session path keeps the
//! configured policy.

use std::time::{Duration, Instant};

use nyaterm_remote_desktop::RdpCertificatePolicy;
use nyaterm_remote_desktop::RdpSessionConfig;
use nyaterm_remote_desktop::activex::{NativeRdpConnectionEvent, NativeRdpRect, validate_start};

use crate::{NativeRdpControl, maintain_retired};

/// Interval between staged drives while waiting for the control to connect.
const TICK: Duration = Duration::from_millis(20);
/// Upper bound for the graceful close after the outcome is decided.
const CLOSE_GRACE: Duration = Duration::from_secs(3);
const PROBE_WIDTH: i32 = 1024;
const PROBE_HEIGHT: i32 = 768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeRdpProbeError {
    message: String,
}

impl NativeRdpProbeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for NativeRdpProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for NativeRdpProbeError {}

/// Connect, complete NLA/CredSSP authentication with the Windows system
/// component, then close the throwaway session.
///
/// Runs on its own STA thread, so the caller may be any worker thread.
pub fn probe_native_rdp(
    config: &RdpSessionConfig,
    timeout: Duration,
    is_cancelled: impl Fn() -> bool + Send + 'static,
) -> Result<(), NativeRdpProbeError> {
    let mut config = config.clone();
    config.certificate_policy = test_certificate_policy(config.certificate_policy);
    config.reconnect.enabled = false;
    config.reconnect.max_attempts = 0;
    let rect = NativeRdpRect {
        x: 0,
        y: 0,
        width: PROBE_WIDTH,
        height: PROBE_HEIGHT,
        scale_percent: 100,
    };
    validate_start(&config, rect).map_err(|error| NativeRdpProbeError::new(error.message))?;

    let spawned = std::thread::Builder::new()
        .name("nyaterm-rdp-probe".into())
        .spawn(move || run_probe(&config, rect, timeout, &is_cancelled))
        .map_err(|error| NativeRdpProbeError::new(format!("RDP probe thread failed: {error}")))?;
    spawned
        .join()
        .unwrap_or_else(|_| Err(NativeRdpProbeError::new("RDP probe thread panicked")))
}

fn test_certificate_policy(policy: RdpCertificatePolicy) -> RdpCertificatePolicy {
    match policy {
        RdpCertificatePolicy::Strict | RdpCertificatePolicy::RejectChanged => policy,
        RdpCertificatePolicy::Prompt
        | RdpCertificatePolicy::TrustOnFirstUse
        | RdpCertificatePolicy::Insecure => RdpCertificatePolicy::Insecure,
    }
}

fn run_probe(
    config: &RdpSessionConfig,
    rect: NativeRdpRect,
    timeout: Duration,
    is_cancelled: &(impl Fn() -> bool + Send),
) -> Result<(), NativeRdpProbeError> {
    let parent = unsafe { probe_window::create(rect.width, rect.height) }?;
    let result = drive_probe(config, rect, parent, timeout, is_cancelled);
    unsafe { probe_window::destroy(parent) };
    maintain_retired(Instant::now());
    result
}
fn drive_probe(
    config: &RdpSessionConfig,
    rect: NativeRdpRect,
    parent: probe_window::ProbeWindow,
    timeout: Duration,
    is_cancelled: &(impl Fn() -> bool + Send),
) -> Result<(), NativeRdpProbeError> {
    let mut control = NativeRdpControl::create(parent.handle(), rect, config)
        .map_err(NativeRdpProbeError::new)?;
    // A system dialog owns a modal loop inside a synchronous COM call, so the
    // deadline below can never fire while one is open. The guard declines those
    // dialogs from another thread, which keeps an unattended test bounded and
    // never approves a security prompt on the user's behalf.
    let guard = native_dialogs::DialogGuard::start();
    let deadline = Instant::now() + timeout;
    let mut outcome = None;
    while outcome.is_none() && Instant::now() < deadline {
        unsafe { probe_window::pump() };
        if is_cancelled() {
            outcome = Some(Err(NativeRdpProbeError::new(
                "RDP test connection was cancelled",
            )));
            break;
        }
        if let Some(operation) = control.take_operation() {
            let completed = operation.run();
            control.commit(completed);
        }
        while let Some(event) = control.poll_connection() {
            match event {
                NativeRdpConnectionEvent::Connected => outcome = Some(Ok(())),
                NativeRdpConnectionEvent::Disconnected(info) => {
                    outcome = Some(Err(NativeRdpProbeError::new(disconnect_message(
                        info.basic_reason,
                        info.extended_reason,
                    ))));
                }
                NativeRdpConnectionEvent::Failed(error) => {
                    outcome = Some(Err(NativeRdpProbeError::new(error.message)));
                }
                NativeRdpConnectionEvent::Reconnecting
                | NativeRdpConnectionEvent::ToggleFullscreen => {}
            }
        }
        if outcome.is_none() {
            std::thread::sleep(TICK);
        }
    }
    let declined_dialog = guard.finish();
    let outcome = outcome.unwrap_or_else(|| {
        Err(NativeRdpProbeError::new(format!(
            "RDP authentication timed out after {}s",
            timeout.as_secs()
        )))
    });
    close_control(&mut control);
    match outcome {
        Err(error) if declined_dialog => Err(NativeRdpProbeError::new(format!(
            "{} (the remote certificate needs interactive approval, which a test never grants)",
            error.message()
        ))),
        other => other,
    }
}

/// Close the throwaway control on its owning thread before the window dies.
fn close_control(control: &mut NativeRdpControl) {
    control.request_shutdown();
    let deadline = Instant::now() + CLOSE_GRACE;
    while !control.is_closed() && Instant::now() < deadline {
        unsafe { probe_window::pump() };
        if let Some(operation) = control.take_operation() {
            let completed = operation.run();
            control.commit(completed);
        }
        if !control.is_closed() {
            std::thread::sleep(TICK);
        }
    }
}

fn disconnect_message(basic: Option<u32>, extended: Option<u32>) -> String {
    match (basic, extended) {
        (Some(basic), Some(extended)) => {
            format!("RDP session disconnected (reason 0x{basic:08X}, extended 0x{extended:08X})")
        }
        (Some(basic), None) => format!("RDP session disconnected (reason 0x{basic:08X})"),
        (None, Some(extended)) => {
            format!("RDP session disconnected (extended reason 0x{extended:08X})")
        }
        (None, None) => "RDP session disconnected".into(),
    }
}

/// Declines system dialogs that a synchronous COM call is waiting on.
///
/// A modal dialog runs its own loop inside the calling thread, so the probe's
/// deadline cannot fire until the dialog closes. Closing it is the
/// security-preserving answer: the test never approves a certificate or a
/// credential prompt, it only refuses to hang forever.
mod native_dialogs {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, GetClassNameW, PostMessageW, WM_CLOSE,
    };
    use windows::core::BOOL;

    const DIALOG_CLASS: &str = "#32770";
    const POLL: Duration = Duration::from_millis(100);

    pub(super) struct DialogGuard {
        stop: Arc<AtomicBool>,
        declined: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl DialogGuard {
        /// Watch the calling thread; call from the thread that owns the control.
        pub(super) fn start() -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let declined = Arc::new(AtomicBool::new(false));
            let thread_id = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };
            let worker_stop = stop.clone();
            let worker_declined = declined.clone();
            let thread = thread::Builder::new()
                .name("nyaterm-rdp-dialogs".into())
                .spawn(move || {
                    while !worker_stop.load(Ordering::Relaxed) {
                        if unsafe { close_dialogs(thread_id) } {
                            worker_declined.store(true, Ordering::Relaxed);
                        }
                        thread::sleep(POLL);
                    }
                })
                .ok();
            Self {
                stop,
                declined,
                thread,
            }
        }

        /// Stop watching and report whether a dialog had to be declined.
        pub(super) fn finish(mut self) -> bool {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
            self.declined.load(Ordering::Relaxed)
        }
    }

    unsafe extern "system" fn visit(
        window: windows::Win32::Foundation::HWND,
        param: LPARAM,
    ) -> BOOL {
        let found = unsafe { &mut *(param.0 as *mut bool) };
        let mut class = [0u16; 32];
        let length = unsafe { GetClassNameW(window, &mut class) };
        if length > 0 && String::from_utf16_lossy(&class[..length as usize]) == DIALOG_CLASS {
            unsafe {
                let _ = PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
            *found = true;
        }
        true.into()
    }

    /// # Safety
    ///
    /// `thread_id` must belong to the probe thread.
    unsafe fn close_dialogs(thread_id: u32) -> bool {
        let mut found = false;
        unsafe {
            let _ = EnumThreadWindows(
                thread_id,
                Some(visit),
                LPARAM(&mut found as *mut bool as isize),
            );
        }
        found
    }
}

/// Minimal hidden parent window plus the message pump the ActiveX control needs.
mod probe_window {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DestroyWindow, DispatchMessageW, MSG, PM_REMOVE, PeekMessageW,
        TranslateMessage, WINDOW_EX_STYLE, WS_POPUP,
    };
    use windows::core::{HSTRING, PCWSTR, w};

    use super::NativeRdpProbeError;

    #[derive(Clone, Copy, Debug)]
    pub(super) struct ProbeWindow(HWND);

    impl ProbeWindow {
        pub(super) fn handle(self) -> isize {
            self.0.0 as isize
        }
    }

    /// Create the hidden parent on the calling (probe) thread.
    ///
    /// A predefined `STATIC` class is reused so no window class registration is
    /// needed and no process-global state outlives the probe.
    ///
    /// # Safety
    ///
    /// Must run on the thread that will own the control and pump messages.
    pub(super) unsafe fn create(
        width: i32,
        height: i32,
    ) -> Result<ProbeWindow, NativeRdpProbeError> {
        let instance = unsafe { GetModuleHandleW(None) }.map_err(|error| {
            NativeRdpProbeError::new(format!("GetModuleHandle failed: {error}"))
        })?;
        let title = HSTRING::from("NyaTerm RDP probe");
        let window = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                w!("STATIC"),
                PCWSTR(title.as_ptr()),
                WS_POPUP,
                0,
                0,
                width,
                height,
                None,
                None,
                Some(instance.into()),
                None,
            )
        }
        .map_err(|error| NativeRdpProbeError::new(format!("RDP probe window failed: {error}")))?;
        Ok(ProbeWindow(window))
    }

    /// Pump this thread's queue so the control receives its callbacks.
    ///
    /// # Safety
    ///
    /// Must run on the thread that created the window.
    pub(super) unsafe fn pump() {
        let mut message = MSG::default();
        while unsafe { PeekMessageW(&mut message, None, 0, 0, PM_REMOVE) }.as_bool() {
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }

    /// Retire the window; the control must already be released.
    ///
    /// # Safety
    ///
    /// Must run on the creating thread after every dependent control is gone.
    pub(super) unsafe fn destroy(window: ProbeWindow) {
        unsafe {
            let _ = DestroyWindow(window.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nyaterm_remote_desktop::{RdpCertificatePolicy, RdpSessionConfig};

    use super::{probe_native_rdp, test_certificate_policy};

    fn config(backend: &str) -> RdpSessionConfig {
        serde_json::from_value(serde_json::json!({
            "backend": backend,
            "windows_authentication": "system",
            "name": "probe fixture",
            "host": "example.invalid",
            "port": 3389,
            "username": "user",
            "domain": "",
            "password": "secret",
            "use_nla": true,
            "certificate_policy": "prompt",
            "display": { "mode": "fit_window", "width": 800, "height": 600, "color_depth": 32 },
            "clipboard": { "mode": "disabled" },
            "reconnect": { "enabled": true, "max_attempts": 5 }
        }))
        .expect("probe fixture")
    }

    #[test]
    fn a_test_never_prompts_for_a_certificate() {
        for policy in [
            RdpCertificatePolicy::Prompt,
            RdpCertificatePolicy::TrustOnFirstUse,
            RdpCertificatePolicy::Insecure,
        ] {
            assert_eq!(
                test_certificate_policy(policy),
                RdpCertificatePolicy::Insecure
            );
        }
        for policy in [
            RdpCertificatePolicy::Strict,
            RdpCertificatePolicy::RejectChanged,
        ] {
            assert_eq!(test_certificate_policy(policy), policy);
        }
    }

    #[test]
    fn the_probe_rejects_a_backend_that_owns_no_system_control() {
        let error = probe_native_rdp(&config("builtin"), Duration::from_secs(5), || false)
            .expect_err("the builtin backend must not start an ActiveX probe");
        assert!(
            error.message().contains("Windows backend"),
            "unexpected error: {error}"
        );
    }

    /// Manual probe against a real server. Provide `NYATERM_RDP_PROBE_HOST`,
    /// `NYATERM_RDP_PROBE_USER` and `NYATERM_RDP_PROBE_PASSWORD`, then run
    /// `cargo test -p nyaterm-windows-rdp --lib live_probe -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_probe() {
        let host = std::env::var("NYATERM_RDP_PROBE_HOST").expect("NYATERM_RDP_PROBE_HOST");
        let user = std::env::var("NYATERM_RDP_PROBE_USER").expect("NYATERM_RDP_PROBE_USER");
        let password =
            std::env::var("NYATERM_RDP_PROBE_PASSWORD").expect("NYATERM_RDP_PROBE_PASSWORD");
        let mut live = config("windows");
        live.host = host;
        live.username = user;
        live.password = Some(password.into());
        live.use_nla = true;
        live.certificate_policy = RdpCertificatePolicy::Insecure;
        let result = probe_native_rdp(&live, Duration::from_secs(45), || false);
        println!("live probe: {result:?}");
        assert!(result.is_ok(), "{result:?}");
    }
}
