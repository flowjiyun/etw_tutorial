use std::{ffi::{OsStr, OsString}, fs::OpenOptions, io::Write, os::windows::ffi::{OsStrExt, OsStringExt}, path::PathBuf, sync::mpsc, thread, time::Duration};

use windows::{core::PWSTR, Win32::{Foundation::ERROR_SUCCESS, System::Diagnostics::Etw::{OpenTraceW, ProcessTrace, TdhGetEventInformation, EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_LOGFILEW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO}}};
use windows_service::{define_windows_service, service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType}, service_control_handler::{self, ServiceControlHandlerResult}, service_dispatcher, Result};

mod audit;
define_windows_service!(ffi_service_main, my_service_main);

fn my_service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service() {
        eprintln!("Error: {:?}", e);
    }
}
fn main() -> Result<()>{
    service_dispatcher::start("MyRustService", ffi_service_main)?;
    Ok(())
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let id = (*event_record).EventHeader.EventDescriptor.Id;
    let message = format!("Event ID: {}", id);
    log_output_to_file(&message);
    print_common_info(event_record);
}

fn run_service() -> Result<()> {
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let service_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                shutdown_tx.send(()).unwrap();
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let service_name = "MyRustService";
    let status_handle = service_control_handler::register(service_name, service_handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    thread::spawn(move || {
        unsafe {
            let session_name = OsStr::new("EventLog-Security").encode_wide().chain(Some(0)).collect::<Vec<u16>>();

            let mut trace_logfile = EVENT_TRACE_LOGFILEW::default();
            trace_logfile.LoggerName = PWSTR(session_name.as_ptr() as *mut u16);
            trace_logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            trace_logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

            let comsumer_handle = OpenTraceW(&mut trace_logfile);

            let status = ProcessTrace(&[comsumer_handle], None, None);
            if status != ERROR_SUCCESS {
                let message = format!("Error: {:?}", status);
                log_output_to_file(&message)
            }
        }
    });

    loop {
        match shutdown_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
            Err(mpsc::RecvTimeoutError::Timeout)  => (),
        }
    }

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: std::time::Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn log_output_to_file(message: &str) {
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

unsafe fn print_common_info(event_record: *mut EVENT_RECORD) {
    let mut buffer_size = 0u32;
    let _status = TdhGetEventInformation(event_record, None, None, &mut buffer_size);
    let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
    let event_info_ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

    let status = TdhGetEventInformation(event_record, None, Some(event_info_ptr), &mut buffer_size);
    if status != 0 {
        eprintln!("tdhgeteventinformation failed with error: {:?}", status);
        return ;
    }
    // print provider name
    if event_info_ptr.as_ref().unwrap().ProviderNameOffset != 0 {
        let provider_name = tei_string(&buffer, event_info_ptr.as_ref().unwrap().ProviderNameOffset as usize);
        let message = format!("provider_name: {}", provider_name);
        log_output_to_file(&message);
    }

    //print task name
    if event_info_ptr.as_ref().unwrap().TaskNameOffset != 0 {
        let task_name = tei_string(&buffer, event_info_ptr.as_ref().unwrap().TaskNameOffset as usize);
        let message = format!("task_name: {}", task_name);
        log_output_to_file(&message);
    }

    let top_level_property = event_info_ptr.as_ref().unwrap().TopLevelPropertyCount;
    let event_info = &*event_info_ptr;
    for i in 0..top_level_property {
        let event_property_info = &*(&event_info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO).offset(i as isize);
        let property_name = tei_string(&buffer, event_property_info.NameOffset as usize);
        let message = format!("property_name: {}", property_name);
        log_output_to_file(&message);
        log_output_to_file("\n");
    }
}

unsafe fn tei_string(tei_buffer: &[u8], offset: usize) -> String {
    let wide_ptr = tei_buffer.as_ptr().add(offset) as *const u16;
    let mut length = 0;

    while *wide_ptr.add(length) != 0 {
        length += 1;
    }
    let wide_slice = core::slice::from_raw_parts(wide_ptr, length);
    let os_string = OsString::from_wide(wide_slice);

    os_string.to_string_lossy().to_string()
}