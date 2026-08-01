// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    /// A mock runner that simulates route table state.
    #[derive(Debug, Default)]
    struct MockRunner {
        preexisting: Mutex<Vec<String>>,
        owned_added: Mutex<Vec<String>>,
        add_fail: Mutex<Vec<String>>,
        last_show: Mutex<Option<String>>,
    }

    impl MockRunner {
        fn with_preexisting(cidr: &str) -> Self {
            Self {
                preexisting: Mutex::new(vec![cidr.to_string()]),
                ..Default::default()
            }
        }
        fn with_add_fail(cidr: &str) -> Self {
            Self {
                add_fail: Mutex::new(vec![cidr.to_string()]),
                ..Default::default()
            }
        }
    }

    impl RouteCommandRunner for MockRunner {
        fn route_show(&self, cidr: &str) -> Result<String, crate::DaemonError> {
            let mut last = self.last_show.lock().unwrap();
            *last = Some(cidr.to_string());
            if self.preexisting.lock().unwrap().iter().any(|p| p == cidr) {
                // Simulate: route exists on the target interface
                Ok(format!("{cidr} dev p2pnet0 scope link"))
            } else {
                Ok(String::new())
            }
        }

        fn route_add(&self, cidr: &str, _interface: &str) -> Result<bool, crate::DaemonError> {
            if self.add_fail.lock().unwrap().iter().any(|f| f == cidr) {
                Ok(false)
            } else {
                self.owned_added.lock().unwrap().push(cidr.to_string());
                Ok(true)
            }
        }

        fn route_del(&self, cidr: &str, _interface: &str) {
            // Simulate successful delete
            let mut owned = self.owned_added.lock().unwrap();
            owned.retain(|o| o != cidr);
        }
    }

    #[test]
    fn test_add_new_route_records_ownership() {
        let runner = Box::new(MockRunner::default());
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(added.len(), 1, "new route should be recorded as owned");
    }

    #[test]
    fn test_preexisting_route_not_recorded() {
        let runner = Box::new(MockRunner::with_preexisting("10.20.0.0/16"));
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(
            added.len(),
            0,
            "pre-existing route on same interface must not be recorded as owned"
        );
    }

    #[test]
    fn test_conflicting_route_on_different_interface_errors() {
        let runner = Box::new(MockRunner::with_preexisting("10.20.0.0/16"));
        // Same preexisting entry but MockRunner always reports dev p2pnet0,
        // so to test conflict we need a different interface RouteManager.
        let rm = RouteManager::new_with_runner("p2pnet1".into(), runner);

        let result = rm.add_cidr_route("10.20.0.0/16");
        assert!(result.is_err(), "conflicting route should return error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("conflict"), "error should mention conflict");
    }

    #[test]
    fn test_cleanup_only_removes_owned_routes() {
        let runner = Box::new(MockRunner::default());
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        rm.add_cidr_route("10.20.0.0/16").unwrap();
        rm.add_cidr_route("192.168.0.0/24").unwrap();

        rm.cleanup();

        let added = rm.routes_added.lock().unwrap();
        assert!(added.is_empty(), "cleanup should clear all owned routes");
    }

    #[test]
    fn test_add_failure_not_recorded() {
        let runner = Box::new(MockRunner::with_add_fail("10.20.0.0/16"));
        let rm = RouteManager::new_with_runner("p2pnet0".into(), runner);

        let result = rm.add_cidr_route("10.20.0.0/16");
        assert!(result.is_err(), "add failure should propagate");

        let added = rm.routes_added.lock().unwrap();
        assert_eq!(
            added.len(),
            0,
            "failed route add must not be recorded as owned"
        );
    }
}

#[cfg(test)]
mod windows_helper_tests {
    use super::*;

    #[test]
    fn detects_managed_windows_interface_aliases() {
        assert!(windows_is_managed_interface_alias("p2wlan"));
        assert!(windows_is_managed_interface_alias("P2WLAN-test"));
        assert!(windows_is_managed_interface_alias("p2pnet0"));
        assert!(!windows_is_managed_interface_alias("Ethernet"));
        assert!(!windows_is_managed_interface_alias("Wi-Fi"));
    }

    #[test]
    fn detects_windows_route_duplicate_errors() {
        assert!(windows_route_already_exists_message(
            "",
            "New-NetRoute : Instance MSFT_NetRoute already exists"
        ));
        assert!(windows_route_already_exists_message(
            "",
            "FullyQualifiedErrorId : Windows System Error 87,New-NetRoute\nMSFT_NetRoute"
        ));
        assert!(windows_route_already_exists_message("", "对象已存在。"));
        assert!(windows_route_already_exists_message("", "路由已存在。"));
        assert!(!windows_route_already_exists_message(
            "",
            "New-NetRoute : Access is denied"
        ));
    }

    #[test]
    fn detects_netsh_route_output_for_interface() {
        let output = "\
Publish  Type      Met  Prefix          Idx  Gateway/Interface Name
-------  --------  ---  --------------  ---  ----------------------
No       Manual    256  10.20.0.0/16     42  p2wlan
No       Manual    256  10.21.0.0/16     43  Ethernet";

        assert!(windows_netsh_route_output_has_interface(
            output,
            "10.20.0.0/16",
            "P2WLAN"
        ));
        assert!(!windows_netsh_route_output_has_interface(
            output,
            "10.21.0.0/16",
            "p2wlan"
        ));
    }
}
