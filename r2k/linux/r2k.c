/* Copyright 2016-2018 - radare2 - MIT - nighterman + pancake + panda + leberus */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/sched/task.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/page-flags.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include "r2k.h"

/*
	- Oscar Salvador <leberus>

		IOCTL_READ_KERNEL_MEMORY	(reads from linear kernel addr)
		IOCTL_WRITE_KERNEL_MEMORY	(writes to linear kernel addr)
		IOCTL_READ_PROCESS_ADDR		(reads from userspace linear addr)
		IOCTL_WRITE_PROCESS_ADDR	(writes to userspace linear addr)
		IOCTL_READ_PHYSICAL_ADDR	(read from physical addr)
		IOCTL_WRITE_PHYSICAL_ADDR	(writes to physical addr)
		IOCTL_GET_KERNEL_MAP


	- Rakholiya Jenish <p4n74>

		IOCTL_READ_REG			(reads from CPU registers)
		IOCTL_PROC_INFO			(reads information about process)
*/

#define  R2_CLASS_NAME  "r2k"

static char *r2_devname = "r2k";

static struct device *r2k_dev_ph;
static struct class *r2k_class;
static struct cdev *r2k_dev;
static dev_t devno;


static struct r2k_map g_r2k_map = {
	{0, 0},
	NULL,
};

static void clean_mmap (void) {
	void *start_addr;
	void *end_addr;
	void *addr;
	int n_pages;

	if (g_r2k_map.map_info) {
		n_pages = g_r2k_map.kernel_maps_info.size / PAGE_SIZE;

		start_addr = g_r2k_map.map_info;
		end_addr = start_addr + (n_pages * PAGE_SIZE);
		for(addr = start_addr; addr < end_addr; addr += PAGE_SIZE)
			ClearPageReserved (vmalloc_to_page ((void*)addr));

		vfree (g_r2k_map.map_info);
		g_r2k_map.map_info = NULL;
	}
}

static int mmap_struct (struct file *filp, struct vm_area_struct *vma) {
	int n_pages;
	void *start_addr;
	void *end_addr;
	void *u_addr;
	void *k_addr;
	unsigned long length;

	n_pages = g_r2k_map.kernel_maps_info.size / PAGE_SIZE;

	start_addr = (void *)g_r2k_map.map_info;
	end_addr = start_addr + (n_pages * PAGE_SIZE);

	length = vma->vm_end - vma->vm_start;

	if (length > g_r2k_map.kernel_maps_info.size) {
		pr_info ("%s: given size if above limit\n", r2_devname);
		return -1;
	}

	for (k_addr = start_addr, u_addr = (void*)(size_t)vma->vm_start;
		k_addr < end_addr; k_addr += PAGE_SIZE) {
		unsigned long pfn = vmalloc_to_pfn (k_addr);
		int ret = remap_pfn_range (vma, (size_t)u_addr, pfn, PAGE_SIZE, PAGE_SHARED);
		if (ret < 0) {
			pr_info ("%s: remap_pfn_range failed\n", r2_devname);
		}
		u_addr += PAGE_SIZE;
	}
	return 0;
}

static bool is_from_module_or_vmalloc (unsigned long addr) {
	return (is_vmalloc_addr ((void *)addr) || __module_address (addr));
}

static bool check_kernel_addr (unsigned long addr) {
	return virt_addr_valid (addr) ? true : is_from_module_or_vmalloc (addr);
}

static int get_nr_pages (unsigned long addr, unsigned long next_aligned_addr, unsigned long len) {
	int nr_pages;

	if (addr & (PAGE_SIZE - 1)) {
		if (addr + len > next_aligned_addr) {
			nr_pages = len < PAGE_SIZE
					? (len / PAGE_SIZE) + 2
					: (len / PAGE_SIZE) + 1;
		} else {
			nr_pages = 1;
		}
	} else {
		 nr_pages = (len & (PAGE_SIZE - 1))
				? len / PAGE_SIZE + 1
				: len / PAGE_SIZE;
	}
	return nr_pages;
}

static inline int get_bytes_to_rw (unsigned long addr, unsigned long len, unsigned long next_aligned_addr) {
	return (len > (next_aligned_addr - addr))
			? next_aligned_addr - addr
			: len;
}

static unsigned long get_next_aligned_addr (unsigned long addr) {
	return (addr & (PAGE_SIZE - 1))
			? PAGE_ALIGN (addr)
			: addr + PAGE_SIZE;
}

static inline void *map_addr (struct page *pg, unsigned long addr) {
	return r2kmap_atomic (pg) + ADDR_OFFSET (addr);
}

static inline void unmap_addr (void *kaddr, unsigned long addr) {
	r2kunmap_atomic (kaddr - ADDR_OFFSET (addr));
}

static int write_vmareastruct (struct vm_area_struct *vma, struct mm_struct *mm,
						struct r2k_proc_info *data,
						unsigned long *count) {
	struct file *file = vma->vm_file;
	dev_t dev = 0;
	char *name = NULL;
	unsigned long ino = 0;
	unsigned long long pgoff = 0;
	unsigned long counter = *count;

	if (counter + 7 > sizeof (data->vmareastruct)) {
		return -ENOMEM;
	}

	if (file) {
		struct inode *inode = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,8,0)
		inode = file_inode (file);
#else
		inode = file->f_path.dentry->d_inode;
#endif
		dev = inode->i_sb->s_dev;
		ino = inode->i_ino;
		pgoff = ((loff_t)vma->vm_pgoff) << PAGE_SHIFT;
	}

	data->vmareastruct[counter]   = vma->vm_start;
	data->vmareastruct[counter+1] = vma->vm_end;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,38) && LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
	if (stack_guard_page_start (vma, vma->vm_start)) {
		data->vmareastruct[counter] += PAGE_SIZE;
	}
	if (stack_guard_page_start (vma, vma->vm_end)) {
		data->vmareastruct[counter+1] -= PAGE_SIZE;
	}
#elif  LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,38) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	if (vma->vm_flags & VM_GROWSDOWN) {
		if (!vma_stack_continue (vma->vm_prev, vma->vm_start)) {
			data->vmareastruct[counter] += PAGE_SIZE;
		}
	}
#endif
	data->vmareastruct[counter + 2] = vma->vm_flags;
	data->vmareastruct[counter + 3] = (unsigned long)pgoff;
	data->vmareastruct[counter + 4] = MAJOR (dev);
	data->vmareastruct[counter + 5] = MINOR (dev);
	data->vmareastruct[counter + 6] = ino;
	counter += 7;

	if (file) {
		name = file->f_path.dentry->d_iname;
		goto write_name;
	}

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,15,0)
	if (vma->vm_ops && vma->vm_ops->name) {
		name = (char *)vma->vm_ops->name (vma);
		if (name) {
			goto write_name;
		}
	}
#endif

	if (!name) {
		if (!mm) {
			name = "[vdso]";
		} else if (vma->vm_start <= mm->brk && vma->vm_end >= mm->start_brk) {
			name = "[heap]";
		} else if (vma->vm_start <= mm->start_stack && vma->vm_end >= mm->start_stack) {
			name = "[stack]";
		}
	}

write_name:
	if (name) {
		int i = 0;
		while (counter * sizeof (unsigned long) + i < sizeof (data->vmareastruct)) {
			*(char *)(((char *)(data->vmareastruct) + counter * sizeof (unsigned long)) + i) = *(char *)(name + i);
			if (*(char *)(name + i) == 0) {
				break;
			}
			i += 1;
		}
		if (counter * sizeof (unsigned long) + i >= sizeof (data->vmareastruct)) {
			return -ENOMEM;
		}
		counter += (i + sizeof (unsigned long) - 1) / sizeof (unsigned long);
	}
	*count = counter;
	return 0;
}

static long io_ioctl (struct file *file, unsigned int cmd, unsigned long data_addr) {
	struct r2k_memory_transf *m_transf;
	struct r2k_map k_map;
	struct r2k_proc_info *proc_inf;
	int ret;

	ret = 0;
	m_transf = NULL;
	proc_inf = NULL;
	k_map.map_info = NULL;

	if (_IOC_TYPE (cmd) != R2_TYPE)
		return -EINVAL;

	switch (_IOC_NR (cmd)) {

	case IOCTL_READ_KERNEL_MEMORY:
	{
		int len;

		m_transf = kmalloc (sizeof (struct r2k_memory_transf), GFP_KERNEL);
		if (!m_transf) {
			ret = -ENOMEM;
			goto out;
		}

		ret = copy_from_user (m_transf, (void __user*)data_addr,
					sizeof (struct r2k_memory_transf));
		if (ret) {
			pr_info ("%s: error - copy struct r2k_memory_transf\n",
								r2_devname);
			ret = -EFAULT;
			goto out;
		}

		len = m_transf->len;
		if (!check_kernel_addr (m_transf->addr)) {
			pr_info ("%s: bad kernel address 0x%lx invalid addr\n", r2_devname,
								m_transf->addr);
			ret = -EFAULT;
			goto out;
		}
		if (!addr_is_mapped (m_transf->addr)) {
			pr_info ("%s: addr is not mapped\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		ret = r2k_copy_to_user (m_transf->buff, (void*)(size_t)m_transf->addr, len);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		break;
	}
	case IOCTL_WRITE_KERNEL_MEMORY:
	{
		int len;

		m_transf = kmalloc (sizeof (struct r2k_memory_transf), GFP_KERNEL);
		if (!m_transf) {
			ret = -ENOMEM;
			goto out;
		}

		ret = copy_from_user (m_transf, (void __user*)data_addr,
					sizeof (struct r2k_memory_transf));
		if (ret) {
			pr_info ("%s: error - copy struct r2k_memory_transf\n",
								r2_devname);
			ret = -EFAULT;
			goto out;
		}

		len = m_transf->len;
		if (!check_kernel_addr (m_transf->addr)) {
			pr_info ("%s: 0x%lx invalid addr\n", r2_devname,
								m_transf->addr);
			ret = -EFAULT;
			goto out;
		}

		if (!addr_is_writeable(m_transf->addr) && m_transf->wp) {
			pr_info ("%s: cannot write at addr 0x%lx\n", r2_devname,
								m_transf->addr);
			ret = -EPERM;
			goto out;
		}

		ret = r2k_copy_from_user((void *)m_transf->addr, m_transf->buff,
								len, m_transf->wp);
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		break;
	}
	case IOCTL_READ_PROCESS_ADDR:
	case IOCTL_WRITE_PROCESS_ADDR:
	{
		struct task_struct *task;
		struct vm_area_struct *vma;
		unsigned long next_aligned_addr;
		void __user *buffer_r;
		int nr_pages;
		int page_i;
		int len;

		m_transf = kmalloc (sizeof (struct r2k_memory_transf), GFP_KERNEL);
		if (!m_transf) {
			ret = -ENOMEM;
			goto out;
		}

		ret = copy_from_user (m_transf, (void __user*)data_addr,
						sizeof (struct r2k_memory_transf));
		if (ret) {
			pr_info ("%s: error - copy struct r2k_memory_transf\n",
								r2_devname);
			ret = -EFAULT;
			goto out;
		}

		buffer_r = m_transf->buff;
		len = m_transf->len;

		task = pid_task (find_vpid (m_transf->pid), PIDTYPE_PID);
		if (!task) {
			pr_info ("%s: could not retrieve task_struct from pid (%d)\n",
					r2_devname, m_transf->pid);
			ret = -ESRCH;
			goto out;
		}
		printk("Task %p + %d\n", task, (int)(size_t)((void*)&task->cred - (void*)task));

		vma = find_vma (task->mm, m_transf->addr);
		if (!vma) {
			pr_info ("%s: could not retrieve vm_area_struct"
								"at 0x%lx\n",
						r2_devname, m_transf->addr);
			ret = -EFAULT;
			goto out;
		}

		if (m_transf->addr + len > vma->vm_end) {
			pr_info ("%s: 0x%lx + %ld bytes goes beyond"
					"valid addresses. bytes recalculated to"
								"%ld bytes\n",
								r2_devname,
								m_transf->addr,
								m_transf->len,
						vma->vm_end - m_transf->addr);
			len = vma->vm_end - m_transf->addr;
		}

		next_aligned_addr = get_next_aligned_addr (m_transf->addr);
		nr_pages = get_nr_pages (m_transf->addr, next_aligned_addr, len);

		down_read (&task->mm->mmap_sem);
		for (page_i = 0 ; page_i < nr_pages ; page_i++ ) {
			struct page *pg = NULL;
			void *kaddr;
			int bytes;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,0,0)
			ret = get_user_pages_remote (task, task->mm, m_transf->addr, 1, 0, &pg, NULL, NULL);
#else
			ret = get_user_pages (task, task->mm, m_transf->addr, 1,
									0,
									0,
									&pg,
									NULL);
#endif
			if (!ret) {
				pr_info ("%s: could not retrieve page"
							"from pid (%d)\n",
							r2_devname,
							m_transf->pid);
				ret = -ESRCH;
				if (pg)
	        			page_cache_release (pg);
				goto out_loop;
			}

			bytes = get_bytes_to_rw (m_transf->addr, len,
							next_aligned_addr);
			kaddr = map_addr (pg, m_transf->addr);

			if (!addr_is_mapped ( (unsigned long)kaddr)) {
				pr_info ("%s: addr is not mapped,"
						"triggering a fault\n", r2_devname);
				unmap_addr (kaddr, m_transf->addr);
				if (pg)
					page_cache_release (pg);
				goto out_loop;
			}

			if (_IOC_NR (cmd) == IOCTL_READ_PROCESS_ADDR)
				ret = r2k_copy_to_user (buffer_r, kaddr, bytes);
			else
				ret = r2k_copy_from_user(kaddr, buffer_r,  bytes, m_transf->wp);

			if (ret) {
				pr_info ("%s: copy_to_user failed\n",
								r2_devname);
				ret = -EFAULT;
				unmap_addr (kaddr, m_transf->addr);
				if (pg)
	        			page_cache_release (pg);
				goto out_loop;
			}

			buffer_r += bytes;
			m_transf->addr = next_aligned_addr;
			next_aligned_addr += PAGE_SIZE;
			len -= bytes;
			unmap_addr (kaddr, m_transf->addr);
			if (pg)
				page_cache_release (pg);
		}

	out_loop:
		up_read (&task->mm->mmap_sem);

		break;
	}
	case IOCTL_READ_PHYSICAL_ADDR:
	case IOCTL_WRITE_PHYSICAL_ADDR:
	{
		void __user *buffer_r;
		int len;

		m_transf = kmalloc (sizeof (struct r2k_memory_transf), GFP_KERNEL);
		if (!m_transf) {
			ret = -ENOMEM;
			goto out;
                }

		ret = copy_from_user (m_transf, (void __user*)data_addr,
					sizeof (struct r2k_memory_transf));
		if (ret) {
			pr_info ("%s: Error copying structure from userspace\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}

		if (!pfn_valid (m_transf->addr >> PAGE_SHIFT)) {
			pr_info ("%s: 0x%lx out of range\n", r2_devname, m_transf->addr);
			ret = -EFAULT;
			goto out;
		}
		buffer_r = m_transf->buff;
		len = m_transf->len;

#if defined (CONFIG_X86_32) || defined (CONFIG_ARM)
		int page_i;
		int nr_pages;
		unsigned long next_aligned_addr;

		next_aligned_addr = get_next_aligned_addr (m_transf->addr);
		nr_pages = get_nr_pages (m_transf->addr, next_aligned_addr, len);

		for (page_i = 0 ; page_i < nr_pages ; page_i++) {
			struct page *pg;
			void *kaddr;
			int bytes;

			bytes = get_bytes_to_rw (m_transf->addr, len,
							next_aligned_addr);

			pg = pfn_to_page (m_transf->addr >> PAGE_SHIFT);
			kaddr = map_addr (pg, m_transf->addr);

			if (_IOC_NR (cmd) == IOCTL_READ_PHYSICAL_ADDR)
				ret = r2k_copy_to_user (buffer_r, kaddr, bytes);
			else {
				if (!addr_is_writeable((unsigned long)kaddr) && m_transf->wp) {
					pr_info ("%s: cannot write at addr "
								"0x%lx\n",
								r2_devname,
							(unsigned long)kaddr);
					unmap_addr (kaddr, m_transf->addr);
					ret = -EPERM;
					goto out;
				}
				ret = r2k_copy_from_user(kaddr, buffer_r, bytes, m_transf->wp);
			}

			if (ret) {
				pr_info ("%s: failed while copying\n",
								r2_devname);
				unmap_addr (kaddr, m_transf->addr);
                	        ret = -EFAULT;
				goto out;
			}

			unmap_addr (kaddr, m_transf->addr);
			buffer_r += bytes;
			m_transf->addr = next_aligned_addr;
			next_aligned_addr += PAGE_SIZE;
			len -= bytes;
		}
#else
		void *kaddr;
		kaddr = phys_to_virt (m_transf->addr);

		if (_IOC_NR (cmd) == IOCTL_READ_PHYSICAL_ADDR) {
			ret = r2k_copy_to_user (buffer_r, kaddr, len);
		} else {
			if (!addr_is_writeable ((unsigned long)kaddr) && m_transf->wp) {
				pr_info ("%s: cannot write at addr %p\n", r2_devname, kaddr);
				ret = -EPERM;
				goto out;
			}
			ret = r2k_copy_from_user(kaddr, buffer_r, len, m_transf->wp);
		}

		if (ret) {
			pr_info ("%s: failed while copying\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}
#endif
		break;
	}
	case IOCTL_GET_KERNEL_MAP:
	{
#if defined (CONFIG_X86_32) || defined (CONFIG_X86_64)
		pr_info ("%s: IOCTL not supported on this arch\n", r2_devname);
		ret = -ENOSYS;
		goto out;
#else
		if (g_r2k_map.map_info) {
			pr_info ("clean\n");
			clean_mmap();
		}

		memset (&k_map, 0, sizeof (k_map));
		ret = pg_dump (&k_map);
		if (ret) {
			if (!k_map.map_info)
				goto out;
		}

		g_r2k_map.kernel_maps_info.size = k_map.kernel_maps_info.size;
		g_r2k_map.kernel_maps_info.n_entries = k_map.kernel_maps_info.n_entries;
		g_r2k_map.map_info = k_map.map_info;

		ret = copy_to_user ((void __user *)data_addr, &k_map.kernel_maps_info, sizeof (struct kernel_maps));
		if (ret) {
			pr_info ("%s: failed while copying\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}
#endif
		break;
	}
	case IOCTL_READ_REG:
	{
		struct r2k_control_reg regs;

#if defined(CONFIG_X86_32) || defined(CONFIG_X86_64)
		regs.cr0 = native_read_cr0 ();
		regs.cr2 = native_read_cr2 ();
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
		regs.cr3 = native_read_cr3 ();
#else
		regs.cr3 = __native_read_cr3 ();
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,9,0)
		regs.cr4 = native_read_cr4_safe ();
#else
		regs.cr4 = native_read_cr4 ();
#endif
#ifdef CONFIG_X86_64
		regs.cr8 = native_read_cr8 ();
#endif
#elif defined (CONFIG_ARM)
		regs.ttbr0 = read_ttbr (0);
		regs.ttbr1 = read_ttbr (1);
		regs.ttbcr = read_ttbcr ();
		regs.c1 = read_c1 ();
		regs.c3 = read_c3 ();
#elif defined (CONFIG_ARM64)
		regs.ttbr0_el1 = read_ttbr0_EL1 ();
		regs.ttbr1_el1 = read_ttbr1_EL1 ();
		regs.tcr_el1 = read_tcr_EL1 ();
		regs.sctlr_el1 = read_sctlr_EL1 ();
#endif
		ret = copy_to_user ((void __user *)data_addr, &regs, sizeof (struct r2k_control_reg));
		if (ret) {
			pr_info ("%s: failed while copying\n", r2_devname);
		}

		break;
	}
	case IOCTL_PROC_INFO:
	{
		unsigned long counter = 0;
		struct task_struct *task = NULL;
		struct mm_struct *mm = NULL;
		struct vm_area_struct *vma = NULL;

		proc_inf = kmalloc (sizeof (*proc_inf), GFP_KERNEL);
		if (!proc_inf) {
			return -ENOMEM;
		}

		memset (proc_inf, 0, sizeof (*proc_inf));
		ret = copy_from_user (&(proc_inf->pid), &(((struct r2k_proc_info __user *)data_addr)->pid), sizeof (pid_t));
		if (ret) {
			ret = -EFAULT;
			goto out;
		}

		task = pid_task (find_vpid (proc_inf->pid), PIDTYPE_PID);
		if (!task) {
			pr_info ("%s: Couldn't retrieve task_struct for pid (%d)\n", r2_devname, proc_inf->pid);
			ret = -ESRCH;
			goto out;
		}

		mm = task->mm;
		vma = mm ? mm->mmap : NULL;

		task_lock(task);
		strncpy (proc_inf->comm, task->comm, sizeof (task->comm));
		task_unlock(task);

		counter = 0;
		if (vma) {
			for (; vma; vma = vma->vm_next) {
				ret = write_vmareastruct (vma, mm, proc_inf, &counter);
				if (ret) {
					pr_info ("write_vmareastruct - error\n");
					goto out;
				}
			}
			//TODO: memory map details on vsyscall address range
		}

#ifdef CONFIG_STACK_GROWSUP
		proc_inf->stack = (unsigned long)task->stack;
#else
		proc_inf->stack = (unsigned long)task->stack + THREAD_SIZE - sizeof (unsigned long);
#endif
		proc_inf->task = (size_t)task;

		ret = copy_to_user ((void *)data_addr, proc_inf, sizeof (*proc_inf));
		if (ret) {
			pr_info ("%s: copy_to_user failed\n", r2_devname);
			ret = -EFAULT;
			goto out;
		}
		break;
	}
	default:
		pr_info ("%s: operation not implemented\n", r2_devname);
		ret = -EINVAL;
		break;
	}

out:
	if (m_transf)
		kfree (m_transf);
	if (k_map.map_info && ret)
		clean_mmap();
	if (proc_inf)
		kfree (proc_inf);

	return ret;
}

static int io_open (struct inode *inode, struct file *file) {
	return 0;
}

static int io_close (struct inode *inode, struct file *file) {
	return 0;
}

static struct file_operations fops = {
        .owner = THIS_MODULE,
        .open = io_open,
        .release = io_close,
        .unlocked_ioctl = io_ioctl,
	.mmap = mmap_struct,
};

static char *r2k_devnode (struct device *dev_ph, umode_t *mode) {
	if (mode) {
		if (dev_ph->devt == devno) {
			*mode = 0600;
		}
	}
	return NULL;
}

static int __init r2k_init (void) {
	int ret;
	pr_info ("%s: loading driver\n", r2_devname);

	ret = alloc_chrdev_region (&devno, 0, 1, r2_devname);
	if (ret < 0) {
		pr_info ("%s: alloc_chrdev_region failed\n", r2_devname);
		goto out;
	}

	r2k_class = class_create (THIS_MODULE, R2_CLASS_NAME);
	if (IS_ERR (r2k_class)) {
		pr_info ("%s: class_create failed creating -r2k- class\n",
								r2_devname);
		ret = PTR_ERR (r2k_class);
		goto out_unreg_dev;
	}

	r2k_class->devnode = r2k_devnode;

	r2k_dev = cdev_alloc();
	if (r2k_dev == NULL) {
		pr_info ("%s: cdev_alloc failed\n", r2_devname);
		ret = -ENOMEM;
		goto out_unreg_class;
	}

	cdev_init (r2k_dev, &fops);
	ret = cdev_add (r2k_dev, devno, 1);
	if (ret < 0) {
		pr_info ("%s: cdev_add failed\n", r2_devname);
		goto out_unreg_class;
	}

	r2k_dev_ph = device_create (r2k_class, NULL, devno, NULL, r2_devname);
	if (IS_ERR (r2k_dev_ph)) {
		pr_info ("%s: device_create failed\n", r2_devname);
		ret = PTR_ERR (r2k_dev_ph);
		goto out_del_cdev;
	}

	pr_info ("%s: /dev/%s created\n", r2_devname, r2_devname);
	pr_info ("%s: WARNING - This module implies a security risk as it allows "
				"direct read/write to the system memory. "
				"Use it only under test systems "
					"at your own risk", r2_devname);

	return 0;

out_del_cdev:
	cdev_del (r2k_dev);

out_unreg_class:
	device_destroy (r2k_class, devno);
	class_unregister (r2k_class);

out_unreg_dev:
	unregister_chrdev_region (devno, 1);

out:
	return ret;
}

static void __exit r2k_exit (void) {
	clean_mmap ();
	device_destroy (r2k_class, devno);
	class_unregister (r2k_class);
	class_destroy (r2k_class);
	cdev_del (r2k_dev);
	unregister_chrdev_region (devno, 1);
	pr_info ("%s: unloading driver, /dev/%s deleted\n",
			r2_devname, r2_devname);
}

module_init (r2k_init);
module_exit (r2k_exit);

MODULE_AUTHOR("Oscar Salvador & Panda");
MODULE_DESCRIPTION("r2k");
MODULE_LICENSE("GPL v2");
