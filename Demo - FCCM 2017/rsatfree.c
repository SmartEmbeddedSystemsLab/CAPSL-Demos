/* ---------------------------------------------
*              Register_Driver
* ----------------------------------------------
* This driver allows reading and writing 32-bit registers from the device
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/uaccess.h> /* Needed for copy_from_user */
#include <asm/io.h> /* Needed for IO Read/Write Functions */
#include <linux/proc_fs.h> /* Needed for Proc File System Functions */
//#include <linux/seq_file.h> /* Needed for Sequence File Operations */
#include <linux/platform_device.h> /* Needed for Platform Driver Functions */
#include <linux/fs.h>

/* Define Driver Name */
#define DRIVER_NAME "rsatfree"

//unsigned long *base_addr; /* Virtual Base Address */
struct resource *res; /* Device Resource Structure */
unsigned long remap_size; /* Device Memory Size */

static int __iomem * device_memory = NULL;
int major;

/* Write operation for /proc/register_driver
* -----------------------------------
* Write a 32-bit value to a register
*/
static ssize_t register_write(struct file *file, const char __user * buf, size_t count, loff_t * ppos)
{
        //char value[16];
	//u32 reg = 0;

	if((*ppos)*2 + count >= remap_size)
	    return 0;

	if (copy_from_user(device_memory+*ppos, buf, count))
	    return -EFAULT;

        //printk("wrote %08lx to address %08lx\n", *buf, device_memory+*ppos);
        //printk("ppos= %lld\n", *ppos);
	return count;
}


/* Read Operation for /proc/register_driver
* ---------------------------------------
* Read a 32-bit value from a register
*/
static ssize_t register_read(struct file *file, const char __user * buf, size_t count, loff_t * ppos)
{
	if((*ppos)*2 + count >= remap_size)
	    return 0;

	if (copy_to_user(buf, device_memory+*ppos, count))
		return -EFAULT;

        //printk("read %08lx from address %08lx\n", *buf, device_memory+*ppos);
        //printk("ppos= %lld\n", *ppos);
	return count;
}

/* Open function for /proc/register_driver
* ------------------------------------
* Do nothing
*/
static int register_open(struct inode *inode, struct file *file)
{
	return 0;
}

/* Release function for /proc/register_driver
* ------------------------------------
* Do nothing
*/
static int register_release(struct inode *inode, struct file *file)
{
	return 0;
}

/* Lseek function for /proc/register_driver
* ------------------------------------
* Change f_pos offset value
*/
static loff_t register_lseek(struct file * file, loff_t offset, int orig)
{
	loff_t ret;
	mutex_lock(&file->f_dentry->d_inode->i_mutex);

	switch (orig) {
		case 0:
			if(offset >= remap_size) {
				ret =  -EINVAL;
				mutex_unlock(&file->f_dentry->d_inode->i_mutex);
				return ret;
			}
			file->f_pos = offset;
			ret = file->f_pos;
			break;

		case 1:
			if(file->f_pos + offset >= remap_size) {
				ret =  -EINVAL;
				mutex_unlock(&file->f_dentry->d_inode->i_mutex);
				return ret;
			}

			file->f_pos += offset;
			ret = file->f_pos;
			break;

		default:
			ret = -EINVAL;
	}
	mutex_unlock(&file->f_dentry->d_inode->i_mutex);
	return ret;
}

/* File Operations for /proc/register_driver */
static const struct file_operations register_driver_operations = {
	.open = register_open,
	.release = register_release,
	.read = register_read,
	.write = register_write,
	.llseek = register_lseek
};

/* Shutdown function for register_driver
* -----------------------------------
* Do nothing
*/
static void register_driver_shutdown(struct platform_device *pdev)
{
	//iowrite32(0, base_addr);
}

/* Remove function for register_driver
* ----------------------------------
* Release virtual address and the memory region requested.
*/
static int register_driver_remove(struct platform_device *pdev)
{
	//register_driver_shutdown(pdev);

	/* Remove /proc/register_driver entry */
	//remove_proc_entry(DRIVER_NAME, NULL);
        unregister_chrdev(major, DRIVER_NAME);

	/* Release mapped virtual address */
	iounmap(device_memory);

	/* Release the region */
	release_mem_region(res->start, remap_size);

	return 0;
}

/* Device Probe function for register_driver
* ------------------------------------
* Get the resource structure from the information in device tree.
* request the memory region needed for the controller, and map it into
* kernel virtual memory space. Create an entry under /proc file system
* and register file operations for that entry.
*/
static int register_driver_probe(struct platform_device *pdev)
{
	//struct proc_dir_entry *register_driver_entry;
	int ret = 0;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "No memory resource\n");
		return -ENODEV;
	}

	remap_size = res->end - res->start + 1;
	if (!request_mem_region(res->start, remap_size, pdev->name)) {
		dev_err(&pdev->dev, "Cannot request IO\n");
		return -ENXIO;
	}

	device_memory = (short __iomem *)ioremap(res->start, remap_size); ////////////////////////////////
	if (device_memory <= 0) {
		dev_err(&pdev->dev, "Couldn't ioremap memory at 0x%08lx\n",
		(unsigned long)res->start);
		ret = -ENOMEM;
		goto err_release_region;
	}

	major = register_chrdev(240, DRIVER_NAME, &register_driver_operations);
	if (major < 0) {
		dev_err(&pdev->dev, "Couldn't create dev entry\n");
		ret = -ENOMEM;
		goto err_create_proc_entry;
	}
        printk(KERN_INFO DRIVER_NAME " resource at PA 0x%08lx Major 240\n", res->start);
	//printk(KERN_INFO DRIVER_NAME " probed at VA 0x%08lx\n",(unsigned long) base_addr);

	return 0;

	err_create_proc_entry:
		iounmap(device_memory);
	err_release_region:
		release_mem_region(res->start, remap_size);

	return ret;
}

/* device match table to match with device node in device tree */
static const struct of_device_id register_driver_of_match[] = {
	{.compatible = "smartes,controller_driver-1.00.a"},
	{},
};

MODULE_DEVICE_TABLE(of, register_driver_of_match);

 /* platform driver structure for myled driver */
 static struct platform_driver register_driver = {
	.driver = {
	.name = DRIVER_NAME,
	.owner = THIS_MODULE,
	.of_match_table = register_driver_of_match},
	.probe = register_driver_probe,
	.remove = register_driver_remove,
	.shutdown = register_driver_shutdown
};

/* Register register_driver platform driver */
module_platform_driver(register_driver);

/* Module Infomations */
MODULE_AUTHOR("SmartES/Digilent");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DRIVER_NAME ": REGISTER_DRIVER (Simple Version)");
MODULE_ALIAS(DRIVER_NAME);
