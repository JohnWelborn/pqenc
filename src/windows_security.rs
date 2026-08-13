//! Windows equivalent of Unix owner-only (`0600`) file modes.
//!
//! Windows has no notion of a `mode` bit passed to `open()`; access is
//! governed by a discretionary access control list (DACL) on the file's
//! security descriptor, which by default is inherited from the parent
//! directory. `create_owner_only` builds a DACL granting full control to
//! exactly the creating user and `SYSTEM`, marks it protected (blocking
//! inherited ACEs from the parent directory), and supplies it to
//! `CreateFileW` so the restriction is established atomically at creation
//! time -- there is no window where the file exists with a weaker ACL, the
//! same guarantee Unix gets from `mode` being part of the `open()` syscall
//! itself.
//!
//! Every fallible step here returns before any file is created, so callers
//! get ordinary fail-closed behavior: a permission error, not a file with a
//! weaker-than-requested ACL.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Opens `path` with a DACL restricted to the current user and `SYSTEM`,
/// applied atomically at creation via `CreateFileW`'s security-attributes
/// argument. `creation_disposition` is a raw Win32 value: pass `CREATE_NEW`
/// for an exclusive create (the Windows analogue of `O_CREAT|O_EXCL`), or
/// `OPEN_ALWAYS` for create-or-reuse (the analogue of `O_CREAT` without
/// `O_EXCL`) -- `CreateFileW` only consults the supplied security
/// descriptor when the call is the one that actually brings the file into
/// existence, so `OPEN_ALWAYS` against a pre-existing file leaves that
/// file's ACL untouched, matching Unix `open()`'s handling of `mode` in the
/// same situation.
pub(crate) fn create_owner_only(path: &Path, creation_disposition: u32) -> io::Result<File> {
    let owner_sid = current_user_sid_string()?;
    // "SY" is the standard SDDL alias for S-1-5-18 (LOCAL SYSTEM); no
    // runtime lookup is needed for it. "P" marks the DACL protected, which
    // blocks inheritable ACEs from the parent directory from merging in --
    // without it, a permissive parent ACL (e.g. Everyone) could still leak
    // through even with only two ACEs listed explicitly. "FA" grants File
    // All Access (full control) to each listed principal.
    let sddl = format!("O:{owner_sid}D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY)");
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();

    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // `sd` is LocalAlloc'd by the call above; every exit path from here
    // must free it exactly once.
    let result = (|| {
        let path_wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let handle: HANDLE = unsafe {
            CreateFileW(
                path_wide.as_ptr(),
                GENERIC_WRITE,
                // Matches std::fs::OpenOptions's own default share mode, so
                // this raw CreateFileW call doesn't also change sharing
                // semantics as a side effect of adding ACL hardening.
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                &sa,
                creation_disposition,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // Safety: `handle` was just returned by CreateFileW above, is not
        // aliased anywhere else, and refers to a plain file -- exactly
        // what `FromRawHandle` requires.
        Ok(unsafe { File::from_raw_handle(handle) })
    })();

    unsafe { LocalFree(sd as _) };
    result
}

/// Fetches the current process's user SID and renders it in `S-1-5-...`
/// string form, for embedding into an SDDL security-descriptor string.
///
/// `pub(crate)`, not private: tests use it directly to compute the expected
/// owner SID when asserting on a created file's DACL, so the expected value
/// is derived through the same code path production uses rather than a
/// second, potentially-drifting implementation.
pub(crate) fn current_user_sid_string() -> io::Result<String> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut needed: u32 = 0;
            // Expected to fail with ERROR_INSUFFICIENT_BUFFER; this first
            // call's only job is to report the buffer size actually
            // needed.
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(io::Error::last_os_error());
            }
            // Backed by a Vec<u64> (not Vec<u8>) so the buffer is
            // guaranteed 8-byte aligned -- required to read it back as a
            // `TOKEN_USER`, which contains a pointer-sized field.
            let mut buf: Vec<u64> = vec![0u64; needed.div_ceil(8) as usize];
            if GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut c_void,
                needed,
                &mut needed,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_to_string(token_user.User.Sid)
        })();
        CloseHandle(token);
        result
    }
}

/// Converts a `PSID` into its `S-1-5-...` string form.
///
/// `pub(crate)`: also used by tests to render grantee SIDs read back out of
/// a created file's DACL.
pub(crate) fn sid_to_string(sid: PSID) -> io::Result<String> {
    unsafe {
        let mut string_sid: *mut u16 = std::ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut string_sid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let len = (0..).take_while(|&i| *string_sid.offset(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, len));
        LocalFree(string_sid as *mut c_void);
        Ok(s)
    }
}
