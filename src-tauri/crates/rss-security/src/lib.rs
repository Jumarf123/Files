use rss_core::RssError;
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcessToken, SetThreadPriority,
        THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct SecurityContext {
    pub is_elevated: bool,
}

pub fn security_context() -> Result<SecurityContext, RssError> {
    Ok(SecurityContext {
        is_elevated: is_process_elevated()
            .map_err(|err| RssError::Message(format!("Failed to query elevation state: {err}")))?,
    })
}

pub fn ensure_elevated() -> Result<(), RssError> {
    let context = security_context()?;
    if context.is_elevated {
        Ok(())
    } else {
        Err(RssError::Message(
            "Administrator privileges are required for raw volume access.".to_string(),
        ))
    }
}

#[derive(Debug)]
pub struct BackgroundThreadGuard(bool);

impl Drop for BackgroundThreadGuard {
    fn drop(&mut self) {
        if self.0 {
            unsafe {
                let _ = SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END);
            }
        }
    }
}

pub fn enter_background_mode_current_thread() -> Result<BackgroundThreadGuard, RssError> {
    unsafe {
        SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN).map_err(|err| {
            RssError::Message(format!("Failed to lower scan thread priority: {err}"))
        })?;
    }
    Ok(BackgroundThreadGuard(true))
}

fn is_process_elevated() -> windows::core::Result<bool> {
    unsafe {
        let mut handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)?;

        let result = (|| -> windows::core::Result<bool> {
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned_length = 0;
            GetTokenInformation(
                handle,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned_length,
            )?;
            Ok(elevation.TokenIsElevated != 0)
        })();

        let _ = CloseHandle(handle);
        result
    }
}
