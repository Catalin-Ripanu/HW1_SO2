// SPDX-License-Identifier: GPL-2.0+

/*
 * Linux kernel list API
 *
 * Author: Cătălin-Alexandru Rîpanu catalin.ripanu@stud.acs.upb.ro
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define PROCFS_MAX_SIZE 512
#define COMMAND_NAME_SIZE 5

#define procfs_dir_name "list"
#define procfs_file_read "preview"
#define procfs_file_write "management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct data_list_elem {
	char *data;
	struct list_head list;
};

static struct list_head kernel_data_list;

DEFINE_RWLOCK(lock);

/**
 * list_proc_show - print elements of the internal kernel list.
 * @m : file structure used for printing in /proc/list/preview.
 */

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;

	read_lock(&lock);

	list_for_each(p, &kernel_data_list) {
		struct data_list_elem *elem;

		elem = list_entry(p, struct data_list_elem, list);
		seq_puts(m, elem->data);
	}

	read_unlock(&lock);

	return 0;
}

static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

/**
 * data_info_alloc - allocate virtual memory from the kernel
 * address space for a list element structure.
 * @data : input char array data received from user space.
 */

static struct data_list_elem *data_info_alloc(char *data)
{
	struct data_list_elem *elem;

	elem = kmalloc(sizeof(*elem), GFP_KERNEL);
	if (elem == NULL)
		return NULL;
	elem->data = data;

	return elem;
}

/**
 * data_add_to_list - add an element to internal kernel list.
 * @data : input char array data received from user space.
 * @option : user's selection regarding the position of
 * the new element in relation to the current head of the list.
 */

static void data_add_to_list(char *data, char *option)
{
	struct data_list_elem *elem;

	if (option == NULL ||
	    (strcmp(option, "after") && strcmp(option, "before")))
		return;

	elem = data_info_alloc(data);

	write_lock(&lock);

	if (!strcmp(option, "after"))
		list_add(&elem->list, &kernel_data_list);
	else if (!strcmp(option, "before"))
		list_add_tail(&elem->list, &kernel_data_list);

	write_unlock(&lock);
}

/**
 * data_add_to_list_before - add an element to kernel list
 * before the current head of this internal list.
 * @data : input char array data received from user space.
 */

static void data_add_to_list_before(char *data)
{
	data_add_to_list(data, "before");
}

/**
 * data_add_to_list_after - add an element to kernel list
 * after the current head of this internal list.
 * @data : input char array data received from user space.
 */

static void data_add_to_list_after(char *data)
{
	data_add_to_list(data, "after");
}

/**
 * data_remove_from_list - remove an element from kernel list.
 * @data : input char array data received from user space.
 * @option : user's selection regarding the algorithm elimination
 * of the new element in relation to it's occurrences.
 */

static void data_remove_from_list(char *data, char *option)
{
	struct list_head *p, *q;

	if (option == NULL ||
	    (strcmp(option, "single") && strcmp(option, "multiple")))
		return;

	write_lock(&lock);

	list_for_each_safe(p, q, &kernel_data_list) {
		struct data_list_elem *elem;

		elem = list_entry(p, struct data_list_elem, list);
		if (!strcmp(elem->data, data)) {
			list_del(p);
			kfree(elem->data);
			kfree(elem);
			if (!strcmp(option, "single"))
				break;
			else if (!strcmp(option, "multiple"))
				continue;
		}
	}

	write_unlock(&lock);
}

/**
 * single_data_remove_from_list - remove the first appearance
 * of an element from kernel list.
 * @data : input char array data received from user space.
 */

static void single_data_remove_from_list(char *data)
{
	data_remove_from_list(data, "single");
}

/**
 * all_common_data_remove_from_list - remove all occurrences
 * of an element from kernel list.
 * @data : input char array data received from user space.
 */

static void all_common_data_remove_from_list(char *data)
{
	data_remove_from_list(data, "multiple");
}

/**
 * extract_input_data - extract input data from a request
 * of the form "echo command_type input_data" made by user.
 * @buffer : input char array data received from user space.
 * @pattern : character which separates "command_type" from
 * "input_data" in user's request.
 */

char *extract_input_data(char *buffer, char pattern)
{
	char *found;
	char *result;
	size_t len;
	int nbefore;

	found = strchr(buffer, pattern);

	if (!found)
		return NULL;

	nbefore = found - buffer;
	len = strlen(buffer) - nbefore;
	result = kmalloc(len, GFP_KERNEL);

	if (result == NULL)
		return NULL;

	strcpy(result, found + 1);

	return result;
}

/**
 * list_write - write input data from user space to /proc/list/preview.
 * @buffer : input char array data received from user space.
 * @count : length of user's request.
 */

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	if (strchr(local_buffer, ' ') != NULL) {
		char command_type[COMMAND_NAME_SIZE];
		char *input_data;

		input_data = extract_input_data(local_buffer, ' ');
		strncpy(command_type, local_buffer, COMMAND_NAME_SIZE - 1);
		command_type[COMMAND_NAME_SIZE - 1] = '\0';

		if (!strcmp(command_type, "addf"))
			data_add_to_list_after(input_data);
		else if (!strcmp(command_type, "adde"))
			data_add_to_list_before(input_data);
		else if (!strcmp(command_type, "delf"))
			single_data_remove_from_list(input_data);
		else if (!strcmp(command_type, "dela"))
			all_common_data_remove_from_list(input_data);
		else
			return 0;
	}

	return local_buffer_size;
}

/**
 * data_list_purge - deallocate all virtual memory from the kernel
 * address space for kernel list.
 */

static void data_list_purge(void)
{
	struct list_head *p, *q;

	write_lock(&lock);

	list_for_each_safe(p, q, &kernel_data_list) {
		struct data_list_elem *elem;

		elem = list_entry(p, struct data_list_elem, list);
		list_del(p);
		kfree(elem->data);
		kfree(elem);
	}

	write_unlock(&lock);
}

static const struct proc_ops r_pops = {
	.proc_open = list_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static const struct proc_ops w_pops = {
	.proc_open = list_write_open,
	.proc_write = list_write,
	.proc_release = single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read =
		proc_create(procfs_file_read, 0000, proc_list, &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write =
		proc_create(procfs_file_write, 0000, proc_list, &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	INIT_LIST_HEAD(&kernel_data_list);

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
	data_list_purge();
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");

MODULE_AUTHOR("Catalin-Alexandru Ripanu catalin.ripanu@stud.acs.upb.ro");
MODULE_LICENSE("GPL v2");
