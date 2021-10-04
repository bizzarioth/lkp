#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/hashtable.h>

#include <linux/kprobes.h>
#include <asm/uaccess.h>

#define MAX_SYMBOL_LEN  64
#define MAX_b 8
static char symbol[MAX_SYMBOL_LEN] = "pick_next_task_fair";
//static char symbol[MAX_SYMBOL_LEN] = "proc_opener";

static struct task_struct * my_task; 
static int counter=0;

// Initialize Hashtable

//static DEFINE_HASHTABLE(myhashtable,MAX_b);

int or = 4;
int bkt = 0;

struct hEntry {
  int val;
  int key;
  struct hlist_node hList;
};
/* For each probe you need to allocate a kprobe structure */
static struct kprobe kproc_open = {
  .symbol_name  = symbol,
};

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund Agarwal]");
MODULE_DESCRIPTION("Project - 3");

//Hash Table increment
void hash_inc(int pid){
  //search pid 
    //increment
  //create if doesnot exist
}

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  int add=0;
  #ifdef CONFIG_X86
    pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
      p->symbol_name, p->addr, regs->ip, regs->flags);
  #endif
  #ifdef CONFIG_ARM64
    pr_info("<%s> p->addr = 0x%p, pc = 0x%lx, pstate = 0x%lx\n",
      p->symbol_name, p->addr, (long)regs->pc, (long)regs->pstate);
  #endif
    /* A dump_stack() here will give a stack backtrace */
  //printk(KERN_INFO "KM PID! %d\n",my_task->pid);
  printk(KERN_INFO "RSI addr = %lx \n",regs->si);
  add=regs->si;
  struct task_struct mytask;
  struct task_struct *myt ;
  if(add){
    my_task = (task_struct*)add;
    printk(KERN_INFO "KM PID: %d\n",my_task->pid);
  
  }else return 0;
  
  //hash_inc(my_task->pid);
  return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
  unsigned long flags)
{
#ifdef CONFIG_X86
  pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
    p->symbol_name, p->addr, regs->flags);
#endif
#ifdef CONFIG_ARM64
  pr_info("<%s> p->addr = 0x%p, pstate = 0x%lx\n",
    p->symbol_name, p->addr, (long)regs->pstate);
#endif
  counter++;
}


static int proc_show(struct seq_file *m, void *v){
  printk(KERN_INFO "Hello world kmesg! %d\n",counter);
  seq_printf(m, "Hello world\n");
  seq_printf(m, "%d\n",counter);
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

static int kprobe_init(void){
  int ret;
  kproc_open.pre_handler = handler_pre;
  kproc_open.post_handler = handler_post;

  ret = register_kprobe(&kproc_open);
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }
  pr_info("Planted kprobe at %p\n", kproc_open.addr);
  return 0;
}

static int __init proj_init(void) {
  int err=0;
  proc_create("perftop", 0, NULL, &myops);

  err+=kprobe_init();
  if(err) return err;
  return 0;
}

static void __exit proj_exit(void) {
  remove_proc_entry("perftop", NULL);

  unregister_kprobe(&kproc_open);
  pr_info("kprobe at %p unregistered\n", kproc_open.addr);

  return;
}

module_init(proj_init);
module_exit(proj_exit);
