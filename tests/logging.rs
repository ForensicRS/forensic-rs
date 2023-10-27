use std::time::Duration;

use forensic_rs::logging::testing_logger_dummy;


#[cfg(not(lib_build))]
#[macro_use]
extern crate forensic_rs;

#[test]
fn test_all_logging() {
    let receiver = testing_logger_dummy();
    error!("This is log name: {}", "PEPE");
    warn!("This is log name: {}", "PEPE");
    info!("This is log name: {}", "PEPE");
    debug!("This is log name: {}", "PEPE");
    trace!("This is log name: {}", "PEPE");
    for _i in 1..6 {
        let msg = receiver
            .recv_timeout(Duration::from_millis(1000))
            .expect("Should send a message");
        println!("{:?}", msg);
    }
}