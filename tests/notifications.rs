use std::time::Duration;

use forensic_rs::notifications::{testing_notifier_dummy, NotificationType};


#[cfg(not(lib_build))]
#[macro_use]
extern crate forensic_rs;

#[test]
fn test_all_notifications() {
    let receiver = testing_notifier_dummy();
    notify_informational!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    notify_info!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    notify_low!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    notify_medium!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    notify_high!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    notify_critical!(NotificationType::AntiForensicsDetected, "This is log name: {}", "PEPE");
    for _i in 0..6 {
        let msg = receiver
            .recv_timeout(Duration::from_millis(1000))
            .expect("Should send a message");
        println!("{:?}", msg);
    }
}