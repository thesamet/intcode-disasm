#[cfg(test)]
pub fn init_logging() {
    use std::io::Write;
    let _ = env_logger::builder()
        .format(|buf, record| writeln!(buf, "{}: {}", record.level(), record.args()))
        .is_test(true)
        .try_init();
}
