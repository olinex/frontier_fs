// @author:    olinex
// @time:      2023/11/30

// self mods

// use other mods
use alloc::string::String;
use enum_group::EnumGroup;
use thiserror_no_std::Error;

// use self mods

#[derive(Error, EnumGroup, Debug)]
pub enum FFSError {
    #[groups(device)]
    #[error("Device id exhausted")]
    DeviceIdExhausted,

    #[groups(device)]
    #[error("NoMoreDeviceMountable")]
    NoMoreDeviceMountable,

    #[groups(device)]
    #[error("Device id does not exist")]
    DeviceIdDoesNotExist(usize),

    #[groups(device)]
    #[error("Busy device undropptable")]
    BusyDeviceUndropptable,

    #[groups(device)]
    #[error("Raw device error code: {0}")]
    RawDeviceError(isize),

    #[groups(device)]
    #[error("Not valid block device data")]
    NotValidBlockDeviceData,

    #[groups(device)]
    #[error("No enough blocks, total blocks must be at least five")]
    NoEnoughBlocks,

    #[groups(block)]
    #[error("No droptable block cache found")]
    NoDroptableBlockCache,

    #[groups(block)]
    #[error("Data out of bounds")]
    DataOutOfBounds,

    #[groups(block)]
    #[error("Block {0} out of bounds")]
    BlockOutOfBounds(usize),

    #[groups(bitmap)]
    #[error("Bitmap was exhausted which start block id is {0}")]
    BitmapExhausted(usize),

    #[groups(bitmap)]
    #[error("Bitmap index {0} was already deallocated")]
    BitmapIndexDeallocated(usize),

    #[groups(vfs)]
    #[error("File name `{0}` was already exists in directory {1}")]
    DuplicatedFname(String, u32),

    #[groups(vfs)]
    #[error("File name `{0}` does not exist in directory {1}")]
    FnameDoesNotExist(String, u32),

    #[groups(vfs)]
    #[error("Can't delete non-empty directory `{0}` from directory {1}")]
    DeleteNonEmptyDirectory(String, u32),

    #[groups(others, parse)]
    #[error("core error: {0}")]
    ParseUtf8Error(#[from] alloc::str::Utf8Error),
}

pub type Result<T> = core::result::Result<T, FFSError>;
