// @author:    olinex
// @time:      2023/11/30

// self mods

// use other mods
use enum_group::EnumGroup;
use thiserror_no_std::Error;

// use self mods

#[derive(Error, EnumGroup, Debug)]
pub enum FFSError {
    #[groups(device)]
    #[error("Not valid block device")]
    NotValidBlockDevice,

    #[groups(block)]
    #[error("No droptable block cache found")]
    NoDroptableBlockCache,

    #[groups(block)]
    #[error("Block {0} out of bounds")]
    BlockOutOfBounds(usize),

    #[groups(block)]
    #[error("Data out of bounds")]
    DataOutOfBounds,

    #[groups(bitmap)]
    #[error("Bitmap was exhausted which start block id is {0}")]
    BitmapExhausted(usize),

    #[groups(bitmap)]
    #[error("Bitmap index {0} was already deallocated")]
    BitmapIndexDeallocated(usize),

    #[groups(vfs)]
    #[error("File name was already exists in directory {0}")]
    DuplicatedFname(u32),

    #[groups(vfs)]
    #[error("File name does not exist in directory {0}")]
    FnameDoesNotExist(u32),

    #[groups(vfs)]
    #[error("Can't delete non-empty directory {0}")]
    DeleteNonEmptyDirectory(u32),

    #[groups(others, parse, core)]
    #[error("core error: {0}")]
    ParseUtf8Error(#[from] alloc::str::Utf8Error),
}

pub type Result<T> = core::result::Result<T, FFSError>;
