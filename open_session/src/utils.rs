use std::{fs::OpenOptions, io::Write, path::PathBuf};

pub fn log_output_to_file(message: &str) {
    let log_message = format!("{}\n", message);
    let log_path = get_log_file_path();
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)
        .unwrap();

    file.write_all(log_message.as_bytes()).unwrap();
}

fn get_log_file_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop();
    path.push("service.log");
    path
}
