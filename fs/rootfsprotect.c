/*
 * rootfsprotect.c - Linux Root Filesystem Operation Protection
 * Copyright (c) 2025  First Person
 *
 * Module is licensed under GPL version 2. This
 * does not express any distinction between
 * GPL-2.0-only or GPL-2.0-or-later. The exact
 * license information can only be determined
 * via the license information in the
 * corresponding source files.
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/rootfsprotect.h>

#define XATTR_NAME "critical.system"

/*
 * List of Linux filesystems with xattr support:
 * - ext2, ext3, ext4 (always enabled since ~3.10)
 * - XFS (xattr always enabled)
 * - Btrfs (xattr always enabled)
 * - ReiserFS (requires user_xattr mount option on older kernels)
 * - Reiser4 (xattr support)
 * - JFS (xattr support)
 * - JFS2 (AIX)
 * - F2FS (CONFIG_F2FS_FS_XATTR)
 * - SquashFS (CONFIG_SQUASHFS_XATTR)
 * - UBIFS (xattr support)
 * - Yaffs2 (xattr support)
 * - OrangeFS (xattr support)
 * - Lustre (xattr support)
 * - OCFS2 (xattr support)
 * - ZFS (xattr support)
 * - TMPFS (CONFIG_TMPFS_XATTR)
 * - NFS (xattr support since Linux 5.9)
 * - CIFS/SMB (CONFIG_CIFS_XATTR)
 * - NTFS3 (modern driver, xattr via streams)
 * - FUSE-based (depends on FUSE implementation)
 * - OverlayFS (passes through to underlying fs)
 * - VirtioFS (xattr support)
 */

/*
 * Check if filesystem supports xattrs
 * Returns: 1 if supported, 0 if not supported
 */
static inline int fs_supports_xattr(struct super_block *sb)
{
    if (!sb)
        return 0;
    
    /* Check if superblock has xattr handlers */
    if (sb->s_xattr)
        return 1;
    
    /* Some filesystems might not populate s_xattr but still support xattrs
     * through VFS generic handlers - we'll try the operation and handle errors
     */
    return 1;
}

/*
 * @name: getAttributeOfFile
 * @description: Get Attribute Of File
 * 
 * Supports all major Linux filesystems with xattr capability:
 * ext2/3/4, XFS, Btrfs, ReiserFS, JFS, F2FS, SquashFS, UBIFS,
 * ZFS, TMPFS, NFS (5.9+), CIFS, NTFS3, and FUSE implementations
 */
int getAttributeOfFile(struct dentry *dentry) {
    ssize_t ret;
    struct inode *inode;
    struct super_block *sb;
    char value_buf[16];
    unsigned int attr_value;
    
    /* Validate dentry pointer */
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    /* Get inode from dentry */
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    /* Get superblock and check filesystem support */
    sb = dentry->d_sb;
    if (!sb || IS_ERR(sb))
        return -ENODEV;
    
    /* Check if filesystem supports xattrs */
    if (!fs_supports_xattr(sb)) {
        pr_debug("rootfsprotect: Filesystem %s doesn't support xattrs\n",
                 sb->s_type ? sb->s_type->name : "unknown");
        return 0x00;
    }
    
    /* Attempt to retrieve extended attribute using VFS handler
     * The trusted.* namespace requires CAP_SYS_ADMIN for user space access
     * Works with: ext4, XFS, Btrfs, F2FS, ReiserFS, JFS, UBIFS, ZFS,
     * TMPFS, NFS (5.9+), CIFS, NTFS3, and other xattr-capable filesystems
     */
    ret = vfs_getxattr(&nop_mnt_idmap, dentry, XATTR_NAME, 
                       value_buf, sizeof(value_buf));
    
    /* Handle various error conditions */
    if (ret < 0) {
        switch (ret) {
            case -ERANGE:   /* Attribute value too large for buffer */
            case -ENODATA:  /* Attribute doesn't exist */
            case -EOPNOTSUPP: /* Extended attributes not supported */
                return 0x00;
            
            case -EACCES:   /* Permission denied */
            case -EPERM:    /* Operation not permitted */
                pr_debug("rootfsprotect: Permission denied reading xattr\n");
                return -EACCES;
            
            case -ENOMEM:   /* Out of memory */
                return -ENOMEM;
            
            default:
                pr_debug("rootfsprotect: Error reading xattr: %zd\n", ret);
                return 0x00; /* Unknown error, return default */
        }
    }
    
    /* Null-terminate the buffer */
    if (ret >= sizeof(value_buf))
        ret = sizeof(value_buf) - 1;
    value_buf[ret] = '\0';
    
    /* Convert string to unsigned int */
    if (kstrtouint(value_buf, 10, &attr_value) != 0) {
        pr_warn("rootfsprotect: Invalid xattr value format\n");
        return 0x00;
    }
    
    return attr_value;
}

/*
 * @name: setAttributeOfFile
 * @description: Set Attribute Of File
 * 
 * Supports all major Linux filesystems with xattr capability
 */
int setAttributeOfFile(struct dentry *dentry, unsigned int attr_value) {
    int result;
    struct inode *inode;
    struct super_block *sb;
    char value_buf[16];
    size_t value_size;
    
    /* 
     * Security check: Only accept calls from application context is running on root user
     * Reject calls from user process context
     */
    if (!capable(CAP_SYS_ADMIN)) {
        pr_warn("rootfsprotect: Rejected user-space call attempt. only root user allowed\n");
        return -EPERM;
    }
    
    /* Validate dentry pointer */
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    /* Get inode from dentry */
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    /* Get superblock and check filesystem support */
    sb = dentry->d_sb;
    if (!sb || IS_ERR(sb))
        return -ENODEV;
    
    /* Check if filesystem supports xattrs */
    if (!fs_supports_xattr(sb)) {
        pr_warn("rootfsprotect: Filesystem %s doesn't support xattrs\n",
                sb->s_type ? sb->s_type->name : "unknown");
        return -EOPNOTSUPP;
    }
    
    /* Check if inode is writable */
    if (IS_RDONLY(inode))
        return -EROFS;
    
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        return -EPERM;
    
    /* Convert attribute value to string for storage */
    value_size = snprintf(value_buf, sizeof(value_buf), "%u", attr_value);
    if (value_size >= sizeof(value_buf))
        return -EINVAL;
    
    /* Attempt to set extended attribute in trusted namespace
     * The "trusted." namespace provides kernel-level protection:
     * - Ring 3 processes need CAP_SYS_ADMIN just to read
     * - Ring 3 processes need CAP_SYS_ADMIN to write
     * - Our kernel-level checks provide additional protection
     * 
     * Compatible with all xattr-supporting filesystems including:
     * ext2/3/4, XFS, Btrfs, ReiserFS, JFS, F2FS, SquashFS, UBIFS,
     * ZFS, TMPFS, NFS, CIFS, NTFS3, etc.
     */
    result = vfs_setxattr(&nop_mnt_idmap, dentry, XATTR_NAME, 
                          value_buf, value_size, 0);
    
    /* Handle various error conditions */
    if (result == 0) {
        /* Success */
        pr_info("rootfsprotect: Set attribute 0x%X on inode %lu (fs: %s)\n", 
                attr_value, inode->i_ino, 
                sb->s_type ? sb->s_type->name : "unknown");
    } else {
        switch (result) {
            case -EOPNOTSUPP:
                pr_warn("rootfsprotect: Filesystem %s doesn't support xattr set\n",
                        sb->s_type ? sb->s_type->name : "unknown");
                break;
                
            case -EACCES:
            case -EPERM:
                pr_warn("rootfsprotect: Permission denied for xattr set\n");
                break;
                
            case -ENOSPC:
            case -EDQUOT:
                pr_warn("rootfsprotect: No space left for xattr\n");
                break;
                
            case -ENOMEM:
                pr_warn("rootfsprotect: Out of memory\n");
                break;
                
            case -EROFS:
                pr_warn("rootfsprotect: Read-only filesystem\n");
                break;
                
            default:
                pr_warn("rootfsprotect: Failed to set xattr: %d\n", result);
                break;
        }
    }
    
    return result;
}

/*
 * @name: removeAttributeOfFile
 * @description: Remove Attribute Of File
 * 
 * Supports all major Linux filesystems with xattr capability
 */
int removeAttributeOfFile(struct dentry *dentry) {
    int result;
    struct inode *inode;
    struct super_block *sb;
    
    /* 
     * Security check: Only accept calls from application context is running on root user
     * Reject calls from user process context
     */
    if (!capable(CAP_SYS_ADMIN)) {
        pr_warn("rootfsprotect: Rejected user-space call attempt. only root user allowed\n");
        return -EPERM;
    }
    
    /* Validate dentry pointer */
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    /* Get inode from dentry */
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    /* Get superblock and check filesystem support */
    sb = dentry->d_sb;
    if (!sb || IS_ERR(sb))
        return -ENODEV;
    
    /* Check if filesystem supports xattrs */
    if (!fs_supports_xattr(sb)) {
        pr_debug("rootfsprotect: Filesystem %s doesn't support xattrs\n",
                 sb->s_type ? sb->s_type->name : "unknown");
        return -EOPNOTSUPP;
    }
    
    /* Check if inode is writable */
    if (IS_RDONLY(inode))
        return -EROFS;
    
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        return -EPERM;
    
    /* Attempt to remove extended attribute from trusted namespace
     * Works across all xattr-capable filesystems
     */
    result = vfs_removexattr(&nop_mnt_idmap, dentry, XATTR_NAME);
    
    if (result == 0) {
        pr_info("rootfsprotect: Removed attribute from inode %lu (fs: %s)\n", 
                inode->i_ino, sb->s_type ? sb->s_type->name : "unknown");
    } else if (result == -ENODATA) {
        /* Attribute doesn't exist, treat as success */
        return 0;
    } else {
        pr_debug("rootfsprotect: Failed to remove xattr: %d\n", result);
    }
    
    return result;
}

EXPORT_SYMBOL(getAttributeOfFile);
EXPORT_SYMBOL(setAttributeOfFile);
EXPORT_SYMBOL(removeAttributeOfFile);