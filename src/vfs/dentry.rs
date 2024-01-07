// @author:    olinex
// @time:      2023/11/22

// self mods

// use other mods

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, sync::Arc, vec};

    use super::super::ffs::FS;
    use super::super::{FileSystem, InitMode};
    use super::*;

    use crate::block::{BlockDevice, MockBlockDevice};

    const HASH_TOTAL_ITEM_COUNT: usize = HASH_GROUP_COUNT * HASH_GROUP_ITEM_COUNT;


    #[test]
    fn test_fname_is_equal() {
        assert!(Fname::empty().is_equal(""));
        assert!(Fname::new("a").is_equal("a"));
        assert!(Fname::new("ab").is_equal("ab"));

        assert!(!Fname::new("a").is_equal("b"));
        assert!(!Fname::new("ab").is_equal("b"));
        assert!(!Fname::new("ba").is_equal("b"));
        assert!(!Fname::new("b").is_equal("ab"));
        assert!(!Fname::new("b").is_equal("ba"));
        assert!(!Fname::new("a").is_equal("ab"));
        assert!(!Fname::new("a").is_equal("ba"));
        assert!(!Fname::new("ab").is_equal("a"));
        assert!(!Fname::new("ba").is_equal("a"));
    }

    #[test]
    fn test_dir_create_and_get_and_remove_child_entry() {
        let device: Arc<dyn BlockDevice> = Arc::new(MockBlockDevice::new());
        // let disk_inode = DiskInode::get(0, 0, &device).unwrap();
        let fs = FS::initialize(InitMode::TotalBlocks(15), 1, &device).unwrap();
        let inode = fs.root_inode();
        let mut mfs = fs.lock();
        let dir = Directory::new(inode);
        // test get and delete entry from empty directory
        assert!(dir.get_child_entry("test").is_ok_and(|i| i.is_none()));
        assert!(dir
            .remove_child_entry("test", &mut mfs)
            .is_err_and(|e| e.is_fnamedoesnotexist()));
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        // test insert and delete entry into empty directory
        assert!(dir
            .create_child_entry("test", FileFlags::empty(), &mut mfs)
            .is_ok_and(|i| i.0.to_str() == "test"
                && i.1.is_valid()
                && !i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.get_child_entry("other").is_ok_and(|i| i.is_none()));
        assert!(dir
            .get_child_entry("test")
            .unwrap()
            .is_some_and(|i| i.0.to_str() == "test"
                && i.1.is_valid()
                && !i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        assert!(dir.remove_child_entry("test", &mut mfs).is_ok());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
        // test insert entry into a non-empty directory
        assert!(dir
            .create_child_entry("other", FileFlags::IS_DIR, &mut mfs)
            .is_ok_and(|i| i.0.to_str() == "other"
                && i.1.is_valid()
                && i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.get_child_entry("test").is_ok_and(|i| i.is_none()));
        assert!(dir
            .get_child_entry("other")
            .unwrap()
            .is_some_and(|i| i.0.to_str() == "other"
                && i.1.is_valid()
                && i.1.is_dir()
                && i.1.inode_bitmap_index == 1));
        assert!(dir.0.leaf_block_count().is_ok_and(|i| i == 1));
        // test insert same hash byte fentry into directory
        // number in list have the same prefix hash byte 9f with "test"
        // those number name files will be stored in the leaf indexes [0, 0, 0, 0, 1, 2, 3, 2, 3]
        for (index, x) in vec![35, 114, 249, 655, 803, 1084, 1500, 1764, 2167]
            .iter()
            .enumerate()
        {
            assert!(dir
                .create_child_entry(x.to_string().as_str(), FileFlags::empty(), &mut mfs)
                .is_ok_and(|i| i.0.to_str() == x.to_string().as_str()
                    && i.1.is_valid()
                    && !i.1.is_dir()
                    && i.1.inode_bitmap_index == (2 + index as u32)));
        }
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("803").unwrap().is_some());
        assert!(dir.remove_child_entry("803", &mut mfs).is_ok());
        assert!(dir.get_child_entry("803").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("2167").unwrap().is_some());
        assert!(dir.remove_child_entry("2167", &mut mfs).is_ok());
        assert!(dir.get_child_entry("2167").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("1764").unwrap().is_some());
        assert!(dir.remove_child_entry("1764", &mut mfs).is_ok());
        assert!(dir.get_child_entry("1764").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 4);

        assert!(dir.get_child_entry("1500").unwrap().is_some());
        assert!(dir.remove_child_entry("1500", &mut mfs).is_ok());
        assert!(dir.get_child_entry("1500").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 3);

        assert!(dir.get_child_entry("1084").unwrap().is_some());
        assert!(dir.remove_child_entry("1084", &mut mfs).is_ok());
        assert!(dir.get_child_entry("1084").unwrap().is_none());
        assert_eq!(dir.0.leaf_block_count().unwrap(), 1);
    }
}
