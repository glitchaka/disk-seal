use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::null_mut,
};
use anyhow::{bail, ensure, Context, Result};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, GetDriveTypeW, GetVolumeInformationW, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING, 
    },
    System::IO::DeviceIoControl,
};
use super::StorageIdentity;
const DRIVE_REMOVABLE: u32 = 2;

// IOCTL_STORAGE_QUERY_PROPERTY = CTL_CODE(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

pub(super) fn capture(executable: &Path) -> Result<StorageIdentity> {
    let path = executable.canonicalize()
        .with_context(|| format!("ejecutable de SST inaccesible: {}", executable.display()))?;
    let raw = path.to_string_lossy();
    let bytes = raw.as_bytes();
    ensure!(bytes.len() >= 3 && bytes[1] == b':' &&
        (bytes[2] == b'\\' || bytes[2] == b'/'),
        "disk-seal sólo admite una instalación local en unidad de Windows");
    let drive = raw.chars().next().unwrap().to_ascii_uppercase();
    let root = format!("{drive}:\\");
    let root_w = wide(OsStr::new(&root));

    let mut volume_serial = 0u32;
    let mut fs_buffer = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(), null_mut(), 0, &mut volume_serial,
            null_mut(), null_mut(), fs_buffer.as_mut_ptr(),
            fs_buffer.len() as u32,
        )
    };
    if ok == 0 {
        bail!("Windows no permitió consultar el volumen {}", root);
    }
    let fs_len = fs_buffer.iter().position(|ch| *ch == 0).unwrap_or(fs_buffer.len());
    let filesystem = String::from_utf16_lossy(&fs_buffer[..fs_len]).to_ascii_uppercase();

    // USB devices can report DRIVE_FIXED on some bridges. The conservative
    // initial policy requires  never silently treats them as USB.
    let removable = unsafe { GetDriveTypeW(root_w.as_ptr()) } == DRIVE_REMOVABLE;
    let serial = query_storage_serial(drive)?;

    Ok(StorageIdentity {
        physical_serial: serial,
        volume_serial: Some(format!("{volume_serial:08X}")),
        filesystem: Some(filesystem),
        removable,
    })
}

fn query_storage_serial(drive: char) -> Result<Option<String>> {
    // Open the volume for metadata only; no write access or sector reads.
    let device_name = format!(r"\\.\{drive}:");
    let name = wide(OsStr::new(&device_name));
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(), OPEN_EXISTING, 0, null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Ok(None);
    }

    let result = (|| -> Result<Option<String>> {
        // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
        let query: [u32; 2] = [0, 0];
        let mut output = [0u8; 2048];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle, IOCTL_STORAGE_QUERY_PROPERTY,
                query.as_ptr().cast(), std::mem::size_of_val(&query) as u32,
                output.as_mut_ptr().cast(), output.len() as u32,
                &mut returned, null_mut(),
            )
        };
        if ok == 0 || returned < 28 { return Ok(None); }
        // STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset is a little-endian u32
        // at byte 24; other fields do not influence the serial lookup.
        let offset = u32::from_le_bytes(output[24..28].try_into()?) as usize;
        if offset < 36 || offset >= returned as usize { return Ok(None); }
        let tail = &output[offset..returned as usize];
        let length = tail.iter().position(|byte| *byte == 0).unwrap_or(tail.len());
        let serial = String::from_utf8_lossy(&tail[..length]).trim().to_ascii_uppercase();
        if serial.is_empty() || serial == "0" { Ok(None) } else { Ok(Some(serial)) }
    })();
    unsafe { CloseHandle(handle); }
    result
}
