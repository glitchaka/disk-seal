//! Windows volume and physical-device inspection.
//! Read-only metadata operations; never mount, format, or modify storage.
use std::{
    ffi::OsStr,
    os::windows::ffi::OsStrExt,
    path::Path,
    ptr::null_mut,
};
use anyhow::{ensure, Context, Result};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW,
        GetVolumeInformationW, OPEN_EXISTING,
    },
    System::IO::DeviceIoControl,
};
use super::StorageIdentity;

const DRIVE_REMOVABLE: u32 = 2;
const BUS_TYPE_USB: u32 = 7;
// CTL_CODE(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002d_1400;
// CTL_CODE(IOCTL_STORAGE_BASE, 0x420, METHOD_BUFFERED, FILE_ANY_ACCESS)
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002d_1080;

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// canonicalize() on Windows normally returns \\?\X:\path, not X:\path.
/// Do not confuse a UNC path with an authenticated local removable volume.
fn canonical_drive_letter(path: &str) -> Option<char> {
    let normal = path.strip_prefix(r"\\?\").unwrap_or(path);
    let bytes = normal.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' ||
        !matches!(bytes[2], b'\\' | b'/') ||
        !bytes[0].is_ascii_alphabetic()
    {
        return None;
    }
    Some((bytes[0] as char).to_ascii_uppercase())
}

pub(super) fn capture(executable: &Path) -> Result<StorageIdentity> {
    let canonical = executable.canonicalize()
        .with_context(|| format!(
            "no se puede inspeccionar el ejecutable {}", executable.display()
        ))?;
    let drive = canonical_drive_letter(&canonical.to_string_lossy())
        .context("disk-seal sólo admite ejecutables en volúmenes locales con letra de unidad")?;
    let root = format!("{drive}:\\");
    let root_w = wide(OsStr::new(&root));
    let mut volume_serial = 0u32;
    let mut filesystem = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(
            root_w.as_ptr(), null_mut(), 0, &mut volume_serial,
            null_mut(), null_mut(), filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    ensure!(ok != 0, "Windows no permitió leer metadatos de {root}");

    let fs_len = filesystem.iter().position(|ch| *ch == 0)
        .unwrap_or(filesystem.len());
    let fs = String::from_utf16_lossy(&filesystem[..fs_len])
        .trim().to_ascii_uppercase();

    let mut volume_device = DeviceProperties::default();
    let mut disk_device = DeviceProperties::default();
    if let Some(handle) = open_metadata_device(&format!(r"\\.\{drive}:")) {
        volume_device = query_properties(handle);
        if let Some(number) = query_device_number(handle) {
            if let Some(physical) = open_metadata_device(
                &format!(r"\\.\PhysicalDrive{number}")
            ) {
                disk_device = query_properties(physical);
                unsafe { CloseHandle(physical); }
            }
        }
        unsafe { CloseHandle(handle); }
    }

    // A Windows USB mass-storage drive can be reported DRIVE_FIXED (3) even
    // though the bus is USB. We require reliable hardware metadata either way.
    let removable = unsafe { GetDriveTypeW(root_w.as_ptr()) } == DRIVE_REMOVABLE
        || disk_device.bus == Some(BUS_TYPE_USB)
        || volume_device.bus == Some(BUS_TYPE_USB);

    Ok(StorageIdentity {
        physical_serial: disk_device.serial.or(volume_device.serial),
        volume_serial: Some(format!("{volume_serial:08X}")),
        filesystem: (!fs.is_empty()).then_some(fs),
        removable,
    })
}

fn open_metadata_device(path: &str) -> Option<HANDLE> {
    let w = wide(OsStr::new(path));
    let handle = unsafe {
        CreateFileW(
            w.as_ptr(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(), OPEN_EXISTING, 0, null_mut(),
        )
    };
    (handle != INVALID_HANDLE_VALUE).then_some(handle)
}

#[derive(Default)]
struct DeviceProperties {
    serial: Option<String>,
    bus: Option<u32>,
}

fn query_properties(handle: HANDLE) -> DeviceProperties {
    // STORAGE_PROPERTY_QUERY (property id = StorageDeviceProperty,
    // query type = PropertyStandardQuery); both fields are u32.
    let query = [0u32, 0u32];
    let mut bytes = [0u8; 4096];
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle, IOCTL_STORAGE_QUERY_PROPERTY,
            query.as_ptr().cast(), std::mem::size_of_val(&query) as u32,
            bytes.as_mut_ptr().cast(), bytes.len() as u32,
            &mut returned, null_mut(),
        )
    };
    if ok == 0 {
        return DeviceProperties::default();
    }
    parse_storage_descriptor(&bytes[..(returned as usize).min(bytes.len())])
}

fn parse_storage_descriptor(buffer: &[u8]) -> DeviceProperties {
    // STORAGE_DEVICE_DESCRIPTOR:
    // SerialNumberOffset at byte 24, BusType at byte 28.
    if buffer.len() < 36 {
        return DeviceProperties::default();
    }
    let offset = u32::from_le_bytes(buffer[24..28].try_into().unwrap()) as usize;
    let bus = u32::from_le_bytes(buffer[28..32].try_into().unwrap());
    let serial = if offset >= 36 && offset < buffer.len() {
        let suffix = &buffer[offset..];
        let count = suffix.iter().position(|ch| *ch == 0).unwrap_or(suffix.len());
        let text = String::from_utf8_lossy(&suffix[..count])
            .trim().to_ascii_uppercase();
        if text.is_empty() || text.chars().all(|ch| matches!(ch, '0' | ' ')) {
            None
        } else {
            Some(text.chars().take(256).collect())
        }
    } else {
        None
    };
    DeviceProperties { serial, bus: Some(bus) }
}

fn query_device_number(handle: HANDLE) -> Option<u32> {
    // STORAGE_DEVICE_NUMBER: DEVICE_TYPE, DeviceNumber, PartitionNumber
    let mut data = [0u8; 12];
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            handle, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            null_mut(), 0,
            data.as_mut_ptr().cast(), data.len() as u32,
            &mut returned, null_mut(),
        )
    };
    if ok == 0 || returned < 12 {
        return None;
    }
    Some(u32::from_le_bytes(data[4..8].try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supports_win32_and_verbatim_drive_paths() {
        assert_eq!(canonical_drive_letter(r"F:\Apps\sst.exe"), Some('F'));
        assert_eq!(canonical_drive_letter(r"\\?\f:\Apps\sst.exe"), Some('F'));
        assert_eq!(canonical_drive_letter(r"\\server\share\sst.exe"), None);
        assert_eq!(canonical_drive_letter(r"\\?\UNC\server\share\sst.exe"), None);
        assert_eq!(canonical_drive_letter(r"\\?\Volume{1234}\sst.exe"), None);
    }
    #[test]
    fn parses_serial_and_usb_bus_metadata() {
        let mut data = [0u8; 64];
        data[24..28].copy_from_slice(&36u32.to_le_bytes());
        data[28..32].copy_from_slice(&BUS_TYPE_USB.to_le_bytes());
        data[36..46].copy_from_slice(b"usb-abc99\0");
        let properties = parse_storage_descriptor(&data);
        assert_eq!(properties.serial.as_deref(), Some("USB-ABC99"));
        assert_eq!(properties.bus, Some(BUS_TYPE_USB));
    }
    #[test]
    fn rejects_short_or_invalid_descriptors() {
        assert!(parse_storage_descriptor(&[0u8; 12]).serial.is_none());
        let mut data = [0u8; 36];
        data[24..28].copy_from_slice(&1024u32.to_le_bytes());
        assert!(parse_storage_descriptor(&data).serial.is_none());
    }
}
