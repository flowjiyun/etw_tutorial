use core::slice;
use std::{ffi::{self, c_char, OsStr, OsString}, os::windows::ffi::{OsStrExt, OsStringExt}, ptr};

use windows::{core::{GUID, PCWSTR, PWSTR}, Win32::{Foundation::ERROR_SUCCESS, System::{Diagnostics::Etw::{CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhFormatProperty, TdhGetEventInformation, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_HEADER_FLAG_STRING_ONLY, EVENT_PROPERTY_INFO, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, TRACE_EVENT_INFO, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID}, Kernel::NtProductLanManNt}}};

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

        let kernel_file_provider_guid = GUID::from_values(
        0xEDD08927,
        0x9CC4,
        0x4E65,
        [0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89],
        );

        let status = EnableTraceEx2(session_handle,
            &kernel_file_provider_guid,
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
        println!("comsumer_handle: {:?}", comsumer_handle);
        loop {
            let status = ProcessTrace(&[comsumer_handle], Some(ptr::null_mut()), Some(ptr::null_mut()));
            if status != ERROR_SUCCESS {
                eprintln!("processtrace failed with error: {:?}", status);
                break;
            } 
        }
        let status = CloseTrace(comsumer_handle); {
            if status != ERROR_SUCCESS {
                eprintln!("closetrace failed with error: {:?}", status);
            }
        }
        let status = ControlTraceW(session_handle, PCWSTR::null(), session_propoerties_ptr, EVENT_TRACE_CONTROL_STOP);
        if status != ERROR_SUCCESS {
            eprintln!("controltrace failed with error: {:?}", status);
        }
    }
}

unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if (*event_record).EventHeader.EventDescriptor.Id == 30 { // 12 open

        println!("event id: {}", (*event_record).EventHeader.EventDescriptor.Id);
        let flag = (*event_record).EventHeader.Flags;
        if flag == EVENT_HEADER_FLAG_STRING_ONLY as u16 { 
            println!("true");
        }

        let mut buffer_size = 0u32;
        let _status = TdhGetEventInformation(event_record, None, None, &mut buffer_size);
        let mut buffer: Vec<u8> = vec![0; buffer_size as usize];
        let event_info_ptr = buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO;

        let status = TdhGetEventInformation(event_record, None, Some(event_info_ptr), &mut buffer_size);
        if status != 0 {
            eprintln!("tdhgeteventinformation failed with error: {:?}", status);
            return ;
        }

        let event_info = &*event_info_ptr;
        let userdata = (*event_record).UserData as *const u8;
        let userdata_slice = slice::from_raw_parts(userdata, (*event_record).UserDataLength as usize);

        for i in 0..event_info.PropertyCount {
            let property_info_ptr = &*(&event_info.EventPropertyInfoArray as *const EVENT_PROPERTY_INFO).offset(i as isize);
            let name_offset = property_info_ptr.NameOffset;
            let _property_name = {
                let name_ptr = (event_info_ptr as *const u8).offset(name_offset as isize);
                ffi::CStr::from_ptr(name_ptr as *const c_char).to_string_lossy().into_owned()
            };
            // println!("property_name: {}", property_name);
            let mut property_buffer_size = 0u32;
            let status = TdhFormatProperty(event_info_ptr,
                 None,
                  8,
                   property_info_ptr.Anonymous1.nonStructType.InType,
                   property_info_ptr.Anonymous1.nonStructType.OutType,
                    property_info_ptr.Anonymous3.length,
                     userdata_slice,
                      &mut property_buffer_size,
                       PWSTR::null(),
                    ptr::null_mut(),
            );

            if status != 0 {
                eprintln!("tdhformatproperty failed with error: {:?}", status);
                return ;
            } 
            let mut property_buffer = vec![0; property_buffer_size as usize];
            let status = TdhFormatProperty(event_info_ptr,
                 None,
                  8,
                   property_info_ptr.Anonymous1.nonStructType.InType,
                   property_info_ptr.Anonymous1.nonStructType.OutType,
                    property_info_ptr.Anonymous3.length,
                     userdata_slice,
                      &mut property_buffer_size,
                       PWSTR(property_buffer.as_mut_ptr()),
                    ptr::null_mut(),
            );
            if status == 0 {
                let formatted_value = OsString::from_wide(&property_buffer).to_string_lossy().into_owned();
                println!("formatted_value: {}", formatted_value);
            }
        } // println!("buffer_size: {}", buffer_size);
    }
}