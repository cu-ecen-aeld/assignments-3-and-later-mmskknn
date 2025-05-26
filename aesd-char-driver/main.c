/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/string.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("mmskknn"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static size_t aesd_buffer_total_content_size(struct aesd_circular_buffer* buffer) {
	size_t total_size = 0;
    uint8_t i;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, i) {
    	total_size += entry->size;
    }

	return total_size;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev;
	dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
	filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence) {
	PDEBUG("aesd_llseek: offset %ld bytes, whence %d", offset, whence);
	
    loff_t retval = 0;
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;
    
    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_llseek: mutex lock failed");
        return -ERESTARTSYS;
    }
    
    size_t total_size = aesd_buffer_total_content_size(&dev->buffer);
    retval = fixed_size_llseek(filp, offset, whence, (loff_t)total_size);
    PDEBUG("aesd_llseek: fixed_size_llseek() return %d", retval);
    
    mutex_unlock(&dev->lock);
    
    return retval;
}

static long aesd_adjust_file_offset(struct file* filp, unsigned int write_cmd, unsigned int write_cmd_offset) {
    long retval = 0;
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_adjust_file_offset: mutex lock failed");
        return -ERESTARTSYS;
    }

	if (write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
		PDEBUG("aesd_adjust_file_offset: invalid write_cmd : %zu", write_cmd);
		retval = -EINVAL;
		goto aesd_adjust_unlock;
	}

	if (write_cmd_offset >= dev->buffer.entry[write_cmd].size) {
		PDEBUG("aesd_adjust_file_offset: invalid write_cmd_offset : %zu", write_cmd_offset);
		retval = -EINVAL;
		goto aesd_adjust_unlock;	
	}

	loff_t start_offset = 0;
	for (int i = 0; i < write_cmd; i++) {
		start_offset += dev->buffer.entry[i].size;
	}
		
	filp->f_pos = start_offset + write_cmd_offset;

aesd_adjust_unlock:
	mutex_unlock(&dev->lock);
    
	return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	PDEBUG("aesd_ioctl: cmd %zu, arg %zu", cmd, arg);
	
	long retval = 0;
	
	switch (cmd) {
	case AESDCHAR_IOCSEEKTO:
	{
		struct aesd_seekto seekto;
		if (copy_from_user(&seekto, (struct aesd_seekto *)arg, sizeof(seekto))) {
			return EFAULT;
		}
		
		retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
		PDEBUG("aesd_ioctl: aesd_adjust_file_offset() return %d", retval);
	}
	default:
		return -EFAULT;
	}
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
     
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_read: mutex lock failed");
        return -ERESTARTSYS;
    }
    
    size_t read_bytes = 0;
    while (read_bytes < count) {
		size_t offset;
		struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &offset);
		if (!entry) {
		    PDEBUG("aesd_read: not enough data is written");
		    goto aesd_read_unlock;
		}
		PDEBUG("aesd_circular_buffer_find_entry_offset_for_fpos: found entry with size=%zu, offset=%zu", entry->size, offset);
    
        size_t bytes_to_read = (count > entry->size - offset) ? entry->size - offset : count;
		if (copy_to_user(buf + read_bytes, entry->buffptr + offset, bytes_to_read)) {
		    PDEBUG("aesd_read: copy_to_user failed");
		    retval = -EFAULT;
		    goto aesd_read_unlock;
		}

	    *f_pos += bytes_to_read;
	    read_bytes += bytes_to_read;
	    PDEBUG("aesd_read: copy_to_user %zu bytes done", bytes_to_read);
		retval = read_bytes;
    }
    
aesd_read_unlock:
    mutex_unlock(&dev->lock);
    
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;

    PDEBUG("aesd_write: received write request of %zu bytes", count);

    if (count == 0) {
        PDEBUG("aesd_write: invalid count size: %zu", count);
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&dev->lock)) {
        PDEBUG("aesd_write: mutex lock failed");
        return -ERESTARTSYS;
    }

    size_t new_size = dev->work.size + count;
    if (new_size < dev->work.size) {
        PDEBUG("aesd_write: size overflow (entry.size=%zu, count=%zu)", dev->work.size, count);
        retval = -EINVAL;
        goto unlock_exit;
    }

    char *new_buff;
    if (dev->work.buffptr) {
        new_buff = krealloc(dev->work.buffptr, new_size, GFP_KERNEL);
        if (!new_buff) {
            PDEBUG("aesd_write: krealloc failed");
            goto unlock_exit;
        }
        dev->work.buffptr = new_buff;
        PDEBUG("aesd_write: buffer extended to %zu bytes", new_size);
    }
    else {
        dev->work.buffptr = kmalloc(new_size, GFP_KERNEL);
        if (!dev->work.buffptr) {
            PDEBUG("aesd_write: kmalloc failed");
            goto unlock_exit;
        }
        PDEBUG("aesd_write: new buffer allocated with size %zu", new_size);
    }

    if (copy_from_user(dev->work.buffptr + dev->work.size, buf, count)) {
        PDEBUG("aesd_write: copy_from_user failed");
        retval = -EFAULT;
        goto unlock_exit;
    }

    dev->work.size = new_size;
    retval = count;

    char *newline = memchr(dev->work.buffptr, '\n', dev->work.size);
    if (newline) {
        size_t commit_size = newline - dev->work.buffptr + 1;
        PDEBUG("aesd_write: newline found at offset %zu", commit_size - 1);

        struct aesd_buffer_entry new_entry = {
            .buffptr = dev->work.buffptr,
            .size = commit_size,
        };

        const char *replaced = aesd_circular_buffer_add_entry(&dev->buffer, &new_entry);
        PDEBUG("aesd_write: committed %zu bytes to circular buffer", commit_size);

		if (replaced) {
			kfree(replaced);
		}

        size_t leftover = dev->work.size - commit_size;
        if (leftover > 0) {
            char *remain = kmalloc(leftover, GFP_KERNEL);
            if (remain) {
                memcpy(remain, dev->work.buffptr + commit_size, leftover);
                PDEBUG("aesd_write: leftover %zu bytes saved for next write", leftover);
            }
            else {
                PDEBUG("aesd_write: kmalloc failed for leftover buffer (size %zu)", leftover);
            }
            dev->work.buffptr = remain;
            dev->work.size = leftover;
        }
        else {
            dev->work.buffptr = NULL;
            dev->work.size = 0;
        }
    }
    else {
        PDEBUG("aesd_write: no newline found, buffering data only");
    }

unlock_exit:
    mutex_unlock(&dev->lock);
    return retval;
}


struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    aesd_circular_buffer_init(&aesd_device.buffer);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    uint8_t i;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, i) {
        kfree(entry->buffptr);
    }

    kfree(aesd_device.work.buffptr);
    aesd_device.work.buffptr = NULL;
    aesd_device.work.size = 0;
    
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
