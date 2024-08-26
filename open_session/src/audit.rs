use std::ptr::null_mut;

use windows::{core::PWSTR, Win32::{Foundation::{HANDLE, STATUS_SUCCESS}, Security::Authentication::Identity::{LsaClose, LsaNtStatusToWinError, LsaOpenPolicy, LsaSetInformationPolicy, PolicyAuditEventsInformation, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, POLICY_AUDIT_EVENTS_INFO, POLICY_AUDIT_EVENT_FAILURE, POLICY_AUDIT_EVENT_SUCCESS, POLICY_SET_AUDIT_REQUIREMENTS, POLICY_VIEW_LOCAL_INFORMATION}}};

pub fn set_audit() {
    unsafe {
        //빈값으로 설정
        let mut policy_handle: LSA_HANDLE = LSA_HANDLE::default();
        let object_attributes = LSA_OBJECT_ATTRIBUTES {
            Length: 0,
            RootDirectory: HANDLE::default(),
            ObjectName: null_mut(),
            Attributes: 0,
            SecurityDescriptor: null_mut(),
            SecurityQualityOfService: null_mut(),
        };


        let mut wide_string: Vec<u16> = "".encode_utf16().collect();
        let pcwstr: PWSTR = PWSTR(wide_string.as_mut_ptr());
        let lsa_string = LSA_UNICODE_STRING {
            Length: (wide_string.len() * 2) as u16,
            MaximumLength : (wide_string.len()*2) as u16,
            Buffer: pcwstr,
        };
        
        // LsaOpenPolicy 함수 호출하여 정책 핸들 열기
        let status = LsaOpenPolicy(
            Some(&lsa_string as * const LSA_UNICODE_STRING),
            &object_attributes as *const LSA_OBJECT_ATTRIBUTES,
            POLICY_VIEW_LOCAL_INFORMATION as u32  | POLICY_SET_AUDIT_REQUIREMENTS as u32,
            &mut policy_handle,
        );

        if status != STATUS_SUCCESS {
            let error_code = LsaNtStatusToWinError(status);
            println!("LsaOpenPolicy failed with error code: {}", error_code);
            return;
        }
    
        
        const EVENT_COUNT: u32= 9 as u32;
        let mut audit_options: [u32; EVENT_COUNT as usize] = [POLICY_AUDIT_EVENT_SUCCESS as u32 | POLICY_AUDIT_EVENT_FAILURE as u32; EVENT_COUNT as usize];

        let policy_info = POLICY_AUDIT_EVENTS_INFO { 
            AuditingMode:false.into(),
            EventAuditingOptions:audit_options.as_mut_ptr(), //https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-policy_audit_event_type
            MaximumAuditEventCount:EVENT_COUNT,
        };

        

        let status = LsaSetInformationPolicy(
            policy_handle,
            PolicyAuditEventsInformation,
            &policy_info as *const _ as *mut _,
        );

        if status != STATUS_SUCCESS {
            let error_code = LsaNtStatusToWinError(status);
            println!("LsaSetInformationPolicy failed with error code: {}", error_code);
            return;
        }

        println!("Audit policy updated successfully.");

        // LsaClose 함수 호출하여 정책 핸들 닫기
        let _ = LsaClose(policy_handle);

    }
}