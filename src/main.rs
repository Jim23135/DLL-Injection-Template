use std::{
    io,
    path::Path,
    os::raw::c_void,
    os::windows::ffi::OsStrExt
};

use windows::{
    core::{
        s, BOOL, PWSTR
    },
    Win32::{
        Foundation::{HWND, LPARAM, TRUE, FALSE},
        UI::WindowsAndMessaging,
        System::{Memory, Threading, LibraryLoader, Diagnostics::Debug as WinDebug},
    }
};

/*
A - ansi (s!())
W - Unicode (w!())
*/

type ThreadProc = unsafe extern "system" fn(*mut c_void) -> u32;

#[derive(Debug)]
struct EnumWindowsData<'a> {
    target: &'a str,
    hwnd: Option<HWND>,
    process_id: Option<u32>
}

unsafe extern "system" fn enum_windows_callback(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let enum_windows_data: &mut EnumWindowsData = unsafe { &mut *(lparam.0 as *mut EnumWindowsData) };

    unsafe {
        // GetWindowThreadProcessId
        // OpenProcess
        // QueryFullProcessImageName
        
        // Get process ID of current window
        let mut process_id: u32 = 0;
        let window_thread_process_id: Option<*mut u32> = Some(&mut process_id as *mut u32);
        WindowsAndMessaging::GetWindowThreadProcessId(hwnd, window_thread_process_id);

        // Open the process
        let process_handle = match Threading::OpenProcess(Threading::PROCESS_QUERY_LIMITED_INFORMATION, false, process_id) {
            Ok(handle) => handle,
            Err(_) => { return FALSE }
        };

        // Get process image name
        let mut out_name_buffer: Vec<u16> = vec![0; 300];
        let out_name = PWSTR(out_name_buffer.as_mut_ptr());

        // This should input the size of out_name_buffer to queryfullprocessimagenamew and will receive the amount of characters written
        let mut name_length: u32 = out_name_buffer.len() as u32;
        match Threading::QueryFullProcessImageNameW(process_handle, Threading::PROCESS_NAME_FORMAT(1), out_name, &mut name_length)  {
            Ok(handle) => handle,
            Err(_) => { return FALSE }
        }
        
        // Remove any bit that is uneeded
        out_name_buffer.truncate(name_length as usize);

        // Try to find the last '\\' in the vec so that from_utf16 doesn't have to work so hard (This alone sped up this search method by like 70%)
        if let Some(position) = out_name_buffer.iter().rposition(|&x| x == '\\' as u16) {
            out_name_buffer.drain(0..=position);

            // Could probably squeeze better performance out by doing str::from_utf8
            let exe_name = String::from_utf16_lossy(&out_name_buffer);

            if exe_name.contains(&enum_windows_data.target) {
                enum_windows_data.hwnd = Some(hwnd);
                enum_windows_data.process_id = Some(process_id);

                return FALSE
            }
        }
    }

    return TRUE
}

fn main() -> Result<(), io::Error> {
    let dll_path = Path::new(r#"E:\dll_to_be_injected.dll"#);

    // Search for target process
    let mut enum_windows_data: EnumWindowsData = EnumWindowsData { target: "Spotify", hwnd: None, process_id: None};

    let _ = unsafe { WindowsAndMessaging::EnumWindows(Some(enum_windows_callback), LPARAM(&mut enum_windows_data as *mut _ as isize)) };

    if enum_windows_data.hwnd.is_none() {
        return Err(io::Error::new(io::ErrorKind::Other, "Process not found."));
    } else {
        println!("Found {}. PID: {}. Proceeding to DLL injection.", enum_windows_data.target, enum_windows_data.process_id.expect("Process ID not found."))
    }

    // Open the process handle witl all access rights
    let process_handle = unsafe { Threading::OpenProcess(Threading::PROCESS_ALL_ACCESS, false, *(&enum_windows_data.process_id.expect("No process but process found."))) }.expect("Unable to open process.");

    // .chain adds the null terminator
    let dll_path_as_wide_string: Vec<u16> = dll_path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    let lp_buffer = dll_path_as_wide_string.as_ptr() as *const c_void;

    // Allocate memmory to write the dll path
    let base_address_allocated_pages = unsafe { Memory::VirtualAllocEx(process_handle, None, dll_path_as_wide_string.len() * size_of::<u16>(), Memory::MEM_COMMIT, Memory::PAGE_READWRITE) };

    let bytes_written_value: usize = 0;
    let bytes_written: Option<*mut usize> = Some(bytes_written_value as *mut usize);

    // Write the dll path
    unsafe { WinDebug::WriteProcessMemory(process_handle, base_address_allocated_pages, lp_buffer, dll_path_as_wide_string.len() * size_of::<u16>(), bytes_written) }?;

    let load_library_w_address = {
        let kernel_32_handle = unsafe { LibraryLoader::GetModuleHandleA(s!("Kernel32.dll")) }.expect("Could not get handle to Kernel32.dll.");
        unsafe { LibraryLoader::GetProcAddress(kernel_32_handle, s!("LoadLibraryW")) }.expect("Unable to find LoadLibraryW.")
    };

    let start_routine: ThreadProc = unsafe { std::mem::transmute(load_library_w_address) };

    let lp_thread_id_value: u32 = 0;
    let lp_thread_id: Option<*mut u32> = Some(lp_thread_id_value as *mut u32);

    // Create remote thread to call loadlibrary
    let remote_thread_handle = unsafe { Threading::CreateRemoteThread(process_handle, None, 0, Some(start_routine), Some(base_address_allocated_pages), 0, lp_thread_id) }?;

    unsafe { Threading::WaitForSingleObject(remote_thread_handle, Threading::INFINITE) };

    match unsafe { Memory::VirtualFreeEx(process_handle, base_address_allocated_pages, 0, Memory::MEM_RELEASE) } {
        Ok(()) => println!("Freed DLL path from target process memory."),
        Err(e) => return Err(e.into())
    }

    Ok(())
}
