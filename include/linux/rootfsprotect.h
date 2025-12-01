/*
 * rootfsprotect.h - Linux Root Filesystem Operation Protection Header
 * Copyright (c) 2025  First Person
 *
 * Module is licensed under GPL version 2. This
 * does not express any distinction between
 * GPL-2.0-only or GPL-2.0-or-later. The exact
 * license information can only be determined
 * via the license information in the
 * corresponding source files.
 */

#ifndef _ROOTFSPROTECT_H
#define _ROOTFSPROTECT_H

#include <linux/types.h>
#include <linux/dcache.h>

/*
 * Extended attribute name used for file protection
 * Uses trusted namespace for kernel-level security
 */
#define XATTR_NAME "critical.system"

/*
 * File attribute flags
 */
#define ATTR_READONLY_FLAG  0xF00F  /* File is read-only protected */
#define ATTR_EDITONLY_FLAG  0x7EA0  /* File allows edits but not deletion */

/*
 * Function prototypes
 */

/**
 * getAttributeOfFile - Retrieve protection attribute from file
 * @dentry: dentry of the file to query
 *
 * Retrieves the protection attribute value from the file's extended
 * attributes. Only callable from kernel space (Ring 0).
 *
 * Return: Attribute value on success, 0x00 if no attribute exists,
 *         negative error code on failure:
 *         -EPERM: Called from user space
 *         -ENODEV: Invalid dentry or inode
 *         -EACCES: Permission denied
 *         -ENOMEM: Out of memory
 */
static unsigned int getAttributeOfFile(struct dentry *dentry);

/**
 * setAttributeOfFile - Set protection attribute on file
 * @dentry: dentry of the file to modify
 * @attr_value: attribute value to set (e.g., ATTR_READONLY_FLAG)
 *
 * Sets the protection attribute on a file using extended attributes.
 * Only callable from kernel space (Ring 0). The attribute is stored
 * in the trusted namespace for enhanced security.
 *
 * Return: 0 on success, negative error code on failure:
 *         -EPERM: Called from user space or immutable inode
 *         -ENODEV: Invalid dentry or inode
 *         -EOPNOTSUPP: Filesystem doesn't support extended attributes
 *         -EACCES: Permission denied
 *         -ENOSPC: No space left on device
 *         -ENOMEM: Out of memory
 *         -EROFS: Read-only filesystem
 *         -EINVAL: Invalid attribute value
 */
static int setAttributeOfFile(struct dentry *dentry, unsigned int attr_value);

/**
 * removeAttributeOfFile - Remove protection attribute from file
 * @dentry: dentry of the file to modify
 *
 * Removes the protection attribute from a file's extended attributes.
 * Only callable from kernel space (Ring 0) in atomic/interrupt context.
 * Additional checks ensure this can only be called from true kernel
 * context, not process context.
 *
 * Return: 0 on success, negative error code on failure:
 *         -EPERM: Called from user space or process context
 *         -ENODEV: Invalid dentry or inode
 *         -EROFS: Read-only filesystem
 */
static int removeAttributeOfFile(struct dentry *dentry);

#endif /* _ROOTFSPROTECT_H */