#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <linux/list.h>

#define BUFSIZE  100

static char *int_str;
static struct proc_dir_entry *ent;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund]");
MODULE_DESCRIPTION("LKP Exercise 4 PROJ 2");

module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);


static int proc_writer(struct seq_file *m, void *v){
    seq_printf(m, "Hello proc!\n");
    seq_printf(m, "LIST ELEMENTS HOW??\n");
    return 0;
}
static int proc_opener(struct inode *in, struct file *f){
    return single_open(f, proc_writer, NULL);
}

//static const struct file_operations myops = 
static const struct proc_ops myops = 
{
// kernel >5.6 make everything .xxx
//    .owner = THIS_MODULE,
    .proc_open = proc_opener,
    .proc_read = seq_read,
    .proc_release = single_release,
};

static int simple_init(void)
{
    ent=proc_create("myprocc",0660,NULL,&myops);
    return 0;
}

static void simple_cleanup(void)
{
    //proc_remove(ent);
    remove_proc_entry("myprocc",NULL);
}

//module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");
module_init(simple_init);
module_exit(simple_cleanup);
