use core::slice;
use std::{collections::HashSet, ffi::{c_void, OsStr, OsString}, os::windows::ffi::{OsStrExt, OsStringExt}, ptr, sync::{Arc, LazyLock, Mutex}};

use windows::{core::{GUID, PCWSTR, PWSTR}, Win32::{Foundation::{CloseHandle, GetLastError, ERROR_SUCCESS}, System::{Diagnostics::Etw::{EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhGetEventInformation, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_STRING_ONLY, EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID}, Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ}}}};

const KERNEL_FILE_GUID: GUID = GUID::from_values(
0xEDD08927,
0x9CC4,
0x4E65,
[0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
);
const KERNEL_PROCESS_GUID: GUID = GUID::from_values(
0x22FB2CD6,
0x0E7B,
0x422B,
[0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16],
);

static PROCESS_LIST: LazyLock<Arc<Mutex<HashSet<u32>>>> = LazyLock::new(|| {
    Arc::new(Mutex::new(HashSet::new()))
});
fn main() {

    unsafe {
        let mut session_properties = vec![0; size_of::<EVENT_TRACE_PROPERTIES>() + 2 * 260];
        let session_propoerties_ptr = session_properties.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        (*session_propoerties_ptr).Wnode.BufferSize = session_properties.len() as u32;
        (*session_propoerties_ptr).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*session_propoerties_ptr).Wnode.ClientContext = 1;
        (*session_propoerties_ptr).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*session_propoerties_ptr).LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let mut session_handle: CONTROLTRACE_HANDLE = CONTROLTRACE_HANDLE { Value: 0 };
        let session_name = OsStr::new("filemonitorsession").encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let session_name_pcwstr = PCWSTR(session_name.as_ptr());
        let status = StartTraceW(&mut session_handle, session_name_pcwstr, session_propoerties_ptr);
        if status != ERROR_SUCCESS {
            eprintln!("starttrace failed with error: {:?}", status);
            return ;
        }

        // 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716

        let status = EnableTraceEx2(session_handle,
            &KERNEL_PROCESS_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                0,
                0,
                0,
                Some(ptr::null_mut())
        );

        if status != ERROR_SUCCESS {
            eprintln!("enabletrace failed with error: {:?}", status);
            return ;
        }

        let status = EnableTraceEx2(session_handle,
            &KERNEL_FILE_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                0,
                0,
                0,
                Some(ptr::null_mut())
        );
        if status != ERROR_SUCCESS {
            eprintln!("enabletrace failed with error: {:?}", status);
            return ;
        }

        let mut trace_logfile = EVENT_TRACE_LOGFILEW::default();
        trace_logfile.LoggerName = PWSTR(session_name.as_ptr() as *mut u16);
        trace_logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        trace_logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);

        let comsumer_handle = OpenTraceW(&mut trace_logfile);

        // 실시간 처리 이벤트의 경우 1개만 handlearray에 넣을 수 있음
        // 파일 처리 이벤트의 경우 64개까지 넣을 수 있음
        // 모든 이벤트를 처리할때 까지 ProcessTrace에서 블로킹블
        // 시작, 끝시간 주지 않았기 때문에 무한으로 이벤트 처리
        let status = ProcessTrace(&[comsumer_handle], Some(ptr::null_mut()), Some(ptr::null_mut()));
        if status != ERROR_SUCCESS {
            eprintln!("processtrace failed with error: {:?}", status);
        } 
    }
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    let fileter_id = {
        if (*event_record).EventHeader.ProviderId == KERNEL_FILE_GUID {
            12
        } else {
            1
        }
    };
    if (*event_record).EventHeader.EventDescriptor.Id == fileter_id { // 10 Create
        let flag = (*event_record).EventHeader.Flags as u32;
        if flag & EVENT_HEADER_FLAG_STRING_ONLY != 0 { 
            println!("true");
        }
        let _pointer_size = {
            if flag & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
                4
            } else {
                8
            }
        };
        if fileter_id == 12{
            let proccess_id = (*event_record).EventHeader.ProcessId; // 실제 파일에 접근하는 프로세스 id
            let set = PROCESS_LIST.lock().unwrap();
            // agent 실행 이후 생성된 프로세스일 경우만 파일 관련 이벤트 출력
            if !set.contains(&proccess_id) {
                return;
            }
            // print_common_info(event_record);
            println!("process_id: {}", proccess_id);
            let file_name_offset = 32;
            let file_name_ptr = (*event_record).UserData as *const u8;
            let file_name = tei_string(slice::from_raw_parts(file_name_ptr, (*event_record).UserDataLength as usize), file_name_offset);
            println!("file_name: {}", file_name);
        } else { // process start event
            let parent_proc_id = (*event_record).EventHeader.ProcessId; // 부모 프로세스 id
            let proc_ptr = (*event_record).UserData as *const u32;
            let proc_id = *proc_ptr; // 생성된  자식 프로세스 id
            let mut set = PROCESS_LIST.lock().unwrap();
            if !set.contains(&proc_id) {
                set.insert(proc_id);
            }
            println!("parent_process_id: {}", parent_proc_id);
            println!("real_proc_id: {}", proc_id);
            let proc_path = get_process_path(proc_id);
            println!("proc_path: {}", proc_path);
            print_common_info(event_record);
        }
    }
}

unsafe fn print_common_info(event_record: *mut EVENT_RECORD) {
    let user_data_size = (*event_record).UserDataLength;
    let user_data = (*event_record).UserData;
    print_hex(user_data, user_data_size as usize);

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
        println!("provider_name: {}", provider_name);
    }

    //print task name
    if event_info_ptr.as_ref().unwrap().TaskNameOffset != 0 {
        let task_name = tei_string(&buffer, event_info_ptr.as_ref().unwrap().TaskNameOffset as usize);
        println!("event_name: {}", task_name);
    }

    let top_level_property = event_info_ptr.as_ref().unwrap().TopLevelPropertyCount;
    let event_info = &*event_info_ptr;
    for i in 0..top_level_property {
        let event_property_info = &*(&event_info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO).offset(i as isize);
        print_event_property_info(event_property_info);
        let property_name = tei_string(&buffer, event_property_info.NameOffset as usize);
        println!("property_name: {}", property_name);
        println!();
    }
}

unsafe fn tei_string(tei_buffer: &[u8], offset: usize) -> String {
    let wide_ptr = tei_buffer.as_ptr().add(offset) as *const u16;
    let mut length = 0;

    while *wide_ptr.add(length) != 0 {
        length += 1;
    }
    let wide_slice = slice::from_raw_parts(wide_ptr, length);
    let os_string = OsString::from_wide(wide_slice);

    os_string.to_string_lossy().to_string()
}

unsafe fn print_hex(buffer: *const c_void, size: usize) {
    if buffer.is_null() {
        println!("buffer is null");
        return;
    }

    let byte_slice = slice::from_raw_parts(buffer as *const u8, size);
    for byte in byte_slice {
        print!("{:02X} ", byte);
    }
    println!();
}

unsafe fn get_process_path(pid: u32) -> String {
    let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("openprocess failed with error: {:?}",e);
            return String::from("cant not get process handle");
        }
    };
    if process_handle.is_invalid() {
        eprintln!("openprocess failed with error: {:?}", GetLastError());
        return String::from("bad path");
    }
    let mut buffer: Vec<u16> = vec![0; 260];
    let mut size = buffer.len() as u32;

    if QueryFullProcessImageNameW(process_handle, PROCESS_NAME_FORMAT(0), PWSTR(buffer.as_mut_ptr() as *mut u16), &mut size).is_ok() {
        let _ = CloseHandle(process_handle);
        let os_string = OsString::from_wide(&buffer[..size as usize]);
        os_string.to_string_lossy().into_owned()
    } else {
        let _ = CloseHandle(process_handle);
        eprintln!("queryfullprocessimagename failed with error: {:?}", GetLastError());
        String::from("bad path")
    }
}

fn print_event_property_info(info: &EVENT_PROPERTY_INFO) {
    println!("property_Flags : {:?}", info.Flags);
    println!("property_NameOffset : {:?}", info.NameOffset);
    if info.Flags.0 & 0x1 != 0 {
        println!("property_StructType");
        unsafe {
            println!("  {:?}", info.Anonymous1.structType);
        }
    } else if info.Flags.0 & 0x1 == 0 {
        println!("property_nonStructType");
        unsafe {
            println!("  {:?}", info.Anonymous1.nonStructType);
        }
    } else if info.Flags.0 & 0x80 !=  0 {
        println!("property_CustomSchema");
        unsafe {
            println!("  {:?}", info.Anonymous1.customSchemaType);
        }
    }
    if info.Flags.0 & 0x4 != 0 {
        unsafe {
            println!("property_countPropertyIndex : {:?}", info.Anonymous2.countPropertyIndex);
        }
    } else {
        unsafe {
            println!("property_count : {:?}", info.Anonymous2.count);
        }
    }
    if info.Flags.0 & 0x2 != 0 {
        unsafe {
            println!("property_lengthPropertyIndex : {:?}", info.Anonymous3.lengthPropertyIndex);
        }
    } else {
        unsafe {
            println!("property_length : {:?}", info.Anonymous3.length);
        }
    }
    unsafe {
        println!("property_reserved : {:?}", info.Anonymous4.Reserved);
    }
    if info.Flags.0 & 0x40 != 0 {
        unsafe {
            println!("property_tags : {:?}", info.Anonymous4.Anonymous._bitfield);
        }
    }
}

// typedef enum _PROPERTY_FLAGS {
//   PropertyStruct = 0x1,
//   PropertyParamLength = 0x2,
//   PropertyParamCount = 0x4,
//   PropertyWBEMXmlFragment = 0x8,
//   PropertyParamFixedLength = 0x10,
//   PropertyParamFixedCount = 0x20,
//   PropertyHasTags = 0x40,
//   PropertyHasCustomSchema = 0x80
// } PROPERTY_FLAGS;