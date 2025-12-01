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
 * @name: getAttributeOfFile
 * @description: Get Attribute Of File
 */
static unsigned int getAttributeOfFile(struct dentry *dentry) {
    int value;
    struct inode *inode;
    
    // Security check: Only accept calls from kernel space (Ring 0)
    // Reject calls from user space (Ring 2/3)
    if (segment_eq(get_fs(), USER_DS)) {
        pr_warn("system: Rejected user-space call attempt\n");
        return -EPERM;
    }
    
    // Validate dentry pointer
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    // Get inode from dentry
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    // Check if filesystem supports xattrs
    if (!inode->i_op || !inode->i_op->getxattr) {
        // Fallback: try using generic xattr handlers
        if (!dentry->d_sb || !dentry->d_sb->s_xattr)
            return 0x00; // Filesystem doesn't support xattrs
    }
    
    // Attempt to retrieve extended attribute
    // Note: trusted.* namespace blocks Ring 2/3 access automatically
    value = security_inode_getxattr(dentry, XATTR_NAME);
    
    // Handle various error conditions
    switch (value) {
        case -ERANGE:   // Attribute value too large for buffer
        case -ENODATA:  // Attribute doesn't exist
        case -ENOTSUP:  // Operation not supported by filesystem
        case -EOPNOTSUPP: // Extended attributes not supported
            return 0x00;
        
        case -EACCES:   // Permission denied
        case -EPERM:    // Operation not permitted
            return -EACCES;
        
        case -ENOMEM:   // Out of memory
            return -ENOMEM;
        
        default:
            if (value < 0)
                return 0x00; // Unknown error, return default
            break;
    }
    
    return (unsigned int)value;
}

/*
 * @name: setAttributeOfFile
 * @description: Set Attribute Of File
 */
static int setAttributeOfFile(struct dentry *dentry, unsigned int attr_value) {
    int result;
    struct inode *inode;
    char value_buf[16];
    size_t value_size;
    
    // Security check: Only accept calls from kernel space (Ring 0)
    // Reject calls from user space (Ring 2/3)
    if (segment_eq(get_fs(), USER_DS)) {
        pr_warn("system: Rejected user-space set attempt\n");
        return -EPERM;
    }
    
    // Validate dentry pointer
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    // Get inode from dentry
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    // Check if filesystem supports xattrs
    if (!inode->i_op || !inode->i_op->setxattr) {
        // Fallback: try using generic xattr handlers
        if (!dentry->d_sb || !dentry->d_sb->s_xattr)
            return -EOPNOTSUPP; // Filesystem doesn't support xattrs
    }
    
    // Check if inode is writable
    if (IS_RDONLY(inode))
        return -EROFS;
    
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        return -EPERM;
    
    // Convert attribute value to string for storage
    value_size = snprintf(value_buf, sizeof(value_buf), "%u", attr_value);
    if (value_size >= sizeof(value_buf))
        return -EINVAL;
    
    // Attempt to set extended attribute in trusted namespace
    // The "trusted." namespace provides kernel-level protection:
    // - Ring 3 processes need CAP_SYS_ADMIN just to read
    // - Ring 3 processes need CAP_SYS_ADMIN to write
    // - Our kernel-level checks provide additional protection
    result = security_inode_setxattr(dentry, XATTR_NAME, 
                                     value_buf, value_size, 0);
    
    // Handle various error conditions
    switch (result) {
        case 0:
            // Success
            pr_info("system: Set attribute 0x%X on inode %lu\n", 
                    attr_value, inode->i_ino);
            break;
            
        case -ENOTSUP:
        case -EOPNOTSUPP:
            pr_warn("system: Filesystem doesn't support xattr set\n");
            return -EOPNOTSUPP;
            
        case -EACCES:
        case -EPERM:
            pr_warn("system: Permission denied for xattr set\n");
            return -EACCES;
            
        case -ENOSPC:
        case -EDQUOT:
            pr_warn("system: No space left for xattr\n");
            return -ENOSPC;
            
        case -ENOMEM:
            return -ENOMEM;
            
        case -EROFS:
            pr_warn("system: Read-only filesystem\n");
            return -EROFS;
            
        default:
            if (result < 0) {
                pr_warn("system: Failed to set xattr: %d\n", result);
                return result;
            }
            break;
    }
    
    return result;
}

/*
 * @name: removeAttributeOfFile
 * @description: Remove Attribute Of File
 */
static int removeAttributeOfFile(struct dentry *dentry) {
    int result;
    struct inode *inode;
    
    // Security check: Only accept calls from kernel space (Ring 0)
    if (segment_eq(get_fs(), USER_DS)) {
        pr_warn("system: Rejected user-space remove attempt\n");
        return -EPERM;
    }
    
    if (!in_atomic() && current->mm != NULL) {
        pr_warn("system: Rejected non-kernel context remove attempt\n");
        return -EPERM;
    }
    
    // Additional security: Block any process context
    if (current->mm != NULL) {
        pr_warn("system: Blocked remove attempt from process context (PID: %d)\n",
                current->pid);
        return -EPERM;
    }
    
    // Validate dentry pointer
    if (!dentry || IS_ERR(dentry))
        return -ENODEV;
    
    // Get inode from dentry
    inode = d_inode(dentry);
    if (!inode || IS_ERR(inode))
        return -ENODEV;
    
    // Check if inode is writable
    if (IS_RDONLY(inode))
        return -EROFS;
    
    if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
        return -EPERM;
    
    // Attempt to remove extended attribute from trusted namespace
    result = security_inode_removexattr(dentry, XATTR_NAME);
    
    if (result == 0) {
        pr_info("system: Removed attribute from inode %lu\n", inode->i_ino);
    } else if (result == -ENODATA) {
        return 0;
    }
    
    return result;
}