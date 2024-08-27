use std::ffi::c_void;

use windows::Win32::{Foundation::{BOOLEAN, STATUS_SUCCESS}, Security::Authentication::Identity::{LsaClose, LsaNtStatusToWinError, LsaOpenPolicy, LsaSetInformationPolicy, PolicyAuditEventsInformation, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, POLICY_AUDIT_EVENTS_INFO, POLICY_AUDIT_EVENT_SUCCESS, POLICY_AUDIT_EVENT_NONE, POLICY_SET_AUDIT_REQUIREMENTS}};

pub fn set_audit() {
    unsafe {
        //빈값으로 설정
        let mut policy_handle: LSA_HANDLE = LSA_HANDLE::default();

        // LSA_OBJECT_ATTRIBUTES 구조체 생성
        // - 모든 필드는 0으로 초기화
        let object_attributes = LSA_OBJECT_ATTRIBUTES::default();
 
        // LsaOpenPolicy 로컬 혹은 원격 시스템의 정책 객체를 생성하는 함수
        let status = LsaOpenPolicy(
            None, // null 일경우 로컬 시스템의 수책을 열수 있음
            &object_attributes as *const LSA_OBJECT_ATTRIBUTES,
            POLICY_SET_AUDIT_REQUIREMENTS as u32,
            &mut policy_handle,
        );

        if status != STATUS_SUCCESS {
            let error_code = LsaNtStatusToWinError(status);
            println!("LsaOpenPolicy failed with error code: {}", error_code);
            return;
        }
    
        
        // typedef enum _POLICY_AUDIT_EVENT_TYPE {
        //     AuditCategorySystem = 0,
        //     AuditCategoryLogon,
        //     AuditCategoryObjectAccess,
        //     AuditCategoryPrivilegeUse,
        //     AuditCategoryDetailedTracking,
        //     AuditCategoryPolicyChange,
        //     AuditCategoryAccountManagement,
        //     AuditCategoryDirectoryServiceAccess,
        //     AuditCategoryAccountLogon
        // } POLICY_AUDIT_EVENT_TYPE, *PPOLICY_AUDIT_EVENT_TYPE

        // 감사 설정할 카테고리 지정
        //https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ne-ntsecapi-policy_audit_event_type
        const EVENT_COUNT: u32= 9 as u32;
        let mut audit_options =  [
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32,
            POLICY_AUDIT_EVENT_SUCCESS as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
            POLICY_AUDIT_EVENT_NONE as u32, 
        ];

        let policy_info = POLICY_AUDIT_EVENTS_INFO { 
            AuditingMode: BOOLEAN::from(true), // true: 감사 활성화, false: 감사 비활성화
            EventAuditingOptions:audit_options.as_mut_ptr(), 
            MaximumAuditEventCount:EVENT_COUNT,
        };

        let status = LsaSetInformationPolicy(
            policy_handle,
            PolicyAuditEventsInformation, // 함수를 통해 조정할 정보의 유형
            &policy_info as *const POLICY_AUDIT_EVENTS_INFO as *const c_void,
        );

        if status != STATUS_SUCCESS {
            let error_code = LsaNtStatusToWinError(status);
            println!("LsaSetInformationPolicy failed with error code: {}", error_code);
            return;
        }

        println!("Audit policy updated successfully.");

        // LsaClose 함수 호출하여 정책 핸들 닫기
        let status = LsaClose(policy_handle);
        if status != STATUS_SUCCESS {
            let error_code = LsaNtStatusToWinError(status);
            println!("LsaClose failed with error code: {}", error_code);
            return;
        }
    }
}