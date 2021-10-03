#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund Agarwal]");
MODULE_DESCRIPTION("Project - 3");

static int proc_show(struct seq_file *m, void *v){
  printk(KERN_INFO "Hello world kmesg!\n");
  seq_printf(m, "Hello world\n");
  return 0;
}
static int proc_opener(struct inode *in, struct file *f){
  return single_open(f, proc_show, NULL);
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos){

  int len=0;
  char buf[100]="myRead says Hello!";

  if(*ppos > 0 || count < 100)
      return 0;
  len += sprintf(buf + len, "\n");

  if(copy_to_user(ubuf,buf,len)) return -EFAULT;

  *ppos = len;
  return len;
}

static const struct proc_ops myops = 
{
  .proc_open = proc_opener,
  .proc_read = seq_read,//myread,
  //.proc_lseek = seq_lseek,
  .proc_release = single_release,
};


static int __init proj_init(void) {
  int err=0;
  proc_create("perftop", 0, NULL, &myops);

  if(err) return err;
  return 0;
}

static void __exit proj_exit(void) {
  remove_proc_entry("perftop", NULL);
  return;
}

module_init(proj_init);
module_exit(proj_exit);
