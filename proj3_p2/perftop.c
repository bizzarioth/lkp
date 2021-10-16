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

#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/jhash.h>

#define MAX_SYMBOL_LEN  64
#define MAX_b 8
#define mBUFSIZE  2000
//size of long[] for stack trace
#define mTrace 64
static char symbol[MAX_SYMBOL_LEN] = "pick_next_task_fair";
//kprobe at kallsyms
static char kallsym_Symbol[MAX_SYMBOL_LEN] = "kallsyms_lookup_name";
static char search_lookup[MAX_SYMBOL_LEN] = "stack_trace_save_user";
/*
>get ADD of kallsyms_lookup_name
>>Create function pointer
>>>pass stack_trace_save_user and get ADD of that
>>>>Create function pointer and use for stact track
*/
static struct task_struct * my_task; 
static int counter=0;

// Initialize Hashtable
static DEFINE_HASHTABLE(myhashtable,MAX_b);
/*Prototype of kallsyms_lookup_name
unsigned long kallsyms_lookup_name(const char *name)
Prototype of stack_trace_save_user
unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
*/
typedef unsigned long func_lookup(const char *name);
typedef unsigned int func_user(unsigned long *store, unsigned int size);

static func_lookup* pointer_lookup_name = NULL;
static func_user* pointer_save_user = NULL;

int or = 4;
int bkt = 0;

struct hEntry {
  int key;
  int val;
  int trace_hash;
  int chk;
  struct hlist_node hList;
};
/* For each probe you need to allocate a kprobe structure */
static struct kprobe kproc_open = {
  .symbol_name  = symbol,
};
static struct kprobe k_kallsym = {
  .symbol_name  = kallsym_Symbol,
};
MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund Agarwal]");
MODULE_DESCRIPTION("Project - 3");

//Hash Table increment
int hash_inc(int pid, int trace_hash){
  struct hEntry *tnode;
  struct hEntry *hnode = kmalloc(sizeof(*hnode), GFP_ATOMIC);
  if(!hnode && sizeof(*hnode))
  {
    return -ENOMEM;
  }
  //search pid(key)

  hash_for_each(myhashtable, bkt, tnode, hList)
  {
    if(pid==tnode->key){
      //found : increment
      tnode->val++;
      //trace check
      tnode->chk = (tnode->trace_hash == trace_hash);
      return 0;
      }
  }

  //create if doesnot exist
  hnode->key = pid;
  hnode->val = 1;
  hnode->trace_hash= trace_hash;
  hnode->chk = 1;
  hash_add(myhashtable,&hnode->hList, hnode->key);
  return 0;
}

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  unsigned long stack_storer[mTrace];
  char pbuff[256];
  int len_trace;
  u32 hashKey;
  //unsigned long symbol_add = kallsyms_lookup_name(stack_user_symbol);
  /*
  #ifdef CONFIG_X86
    pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
      p->symbol_name, p->addr, regs->ip, regs->flags);
  #endif
  */
  /* A dump_stack() here will give a stack backtrace */
  //printk(KERN_INFO "KM PID! %d\n",my_task->pid);
  printk(KERN_INFO "RSI addr = %lx \n",regs->si);

  if((regs->si)==0) return 0;

  my_task = (struct task_struct *)regs->si;
  /*
  Use stack_trace_save function for a kernel task
  Use save_stack_trace_user function for a user task
  -----> use instead stack_trace_save_user
  mm==NULL means kernel task
  */
  printk(KERN_INFO "KM PID: %d task_struct->mm = %pB",my_task->pid, my_task->mm);
  if(my_task->mm){
    //user thread
    //len_trace=stack_trace_save_user(stack_storer,mTrace);
    printk(KERN_INFO "USER PID\n");
    len_trace = pointer_save_user(stack_storer, mTrace);
    printk(KERN_INFO "USER PID Stack Trace\n");
    stack_trace_print(stack_storer,len_trace,5);
    hashKey= jhash(stack_storer ,len_trace*sizeof(unsigned long) ,JHASH_INITVAL);
    printk(KERN_INFO "USER jhash:: %d", hashKey);
    /*
      strncpy(pbuff, (char *)symbol_add, 255); 
      printk(KERN_INFO "[%s] %s (0x%lx): %s\n", __this_module.name, stack_user_symbol, symbol_add,pbuff );
    */
  }else{
    //kernel thread
    len_trace = stack_trace_save(stack_storer,mTrace,0);
    //printk(KERN_INFO "CHECLL:HERE");
    //stack_trace_print(stack_storer,len_trace,5);
    hashKey= jhash(stack_storer ,len_trace*sizeof(unsigned long) ,JHASH_INITVAL);
    printk(KERN_INFO "jhash:: %d", hashKey);
  }
  hash_inc((int)my_task->pid, (int)hashKey);

  counter = my_task->pid;
  return 0;
}
static int __kprobes handler_pre_kallsym(struct kprobe *p, struct pt_regs *regs)
{
  /*
    unsigned long stack_storer[mTrace];
    char pbuff[256];
    int len_trace;
    u32 hashKey;
    //-----KALLSYMS PROBE
    
    #ifdef CONFIG_X86
      pr_info("kallsyms <%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
        p->symbol_name, p->addr, regs->ip, regs->flags);
    #endif
    // A dump_stack() here will give a stack backtrace
    //printk(KERN_INFO "KM PID! %d\n",my_task->pid);
    printk(KERN_INFO "KALLSYMS RSI = %lx \n",regs->si);
  */
  printk(KERN_INFO "KALLSYMS PREHANDLER");
  if((regs->si)==0) return 0;

  /*
    my_task = (struct task_struct *)regs->si;
    Use stack_trace_save function for a kernel task
    Use save_stack_trace_user function for a user task
    -----> use instead stack_trace_save_user
    mm==NULL >means> kernel task
    */
    //printk(KERN_INFO "KM kallsyms PID: %d\n task_struct->mm = %pB",my_task->pid, my_task->mm);
    /*
    if(my_task->mm){
      //user thread
      printk(KERN_INFO "KALLSYUSER PID\n");
      }else{
      //kernel thread
      len_trace = stack_trace_save(stack_storer,mTrace,0);
      printk(KERN_INFO "CHECLL:HERE");// %*c%pS\n ",3,' ',(void *)stack_storer[0]);
      stack_trace_print(stack_storer,len_trace,5);
      //printk(KERN_INFO "\n TRACE: %s",pbuff);
      hashKey= jhash(stack_storer ,len_trace*sizeof(unsigned long) ,JHASH_INITVAL);
      printk(KERN_INFO "jhash:: %d", hashKey);
    }
    //hash_inc((int)my_task->pid, (int)hashKey);
  */
 return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
  unsigned long flags){
  /*
    #ifdef CONFIG_X86
      pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
        p->symbol_name, p->addr, regs->flags);
    #endif
    #ifdef CONFIG_ARM64
      pr_info("<%s> p->addr = 0x%p, pstate = 0x%lx\n",
        p->symbol_name, p->addr, (long)regs->pstate);
    #endif
  */
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
  char buf[mBUFSIZE];
  struct hEntry *hnode;


  if(*ppos > 0 || count < mBUFSIZE)
      return 0;
  len += sprintf(buf,"Hash Table: \n");
  len += sprintf(buf," PID	|	Times Called	|	JHash	|	Same?\n");
  
  hash_for_each(myhashtable, bkt, hnode, hList)
  {
    
    len += sprintf(buf + len," %d	|	%d	|	%d	|	%d\n ",hnode->key,hnode->val, hnode->trace_hash, hnode->chk);

  }

  len += sprintf(buf + len, "\n");

  if(copy_to_user(ubuf,buf,len)) return -EFAULT;

  *ppos = len;
  return len;
}

static const struct proc_ops myops = 
{
  .proc_open = proc_opener,
//  .proc_read = seq_read,
.proc_read = myread,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int kprobe_init(void){
  int ret,ret_kallsym;
  kproc_open.pre_handler = handler_pre;
  kproc_open.post_handler = handler_post;

  k_kallsym.pre_handler = handler_pre_kallsym;
  k_kallsym.post_handler = handler_post;
  
  ret_kallsym = register_kprobe(&k_kallsym);
  if (ret_kallsym < 0) {
    pr_err("register k_kallsym failed, returned %d\n", ret_kallsym);
    return ret_kallsym;
  }
  pr_info("Planted k_kallsym probe at %p\n", k_kallsym.addr);
  /* Get pointers to lookup and save_user*/
  pointer_lookup_name = (func_lookup*)k_kallsym.addr;
  printk(KERN_INFO "CALL lookup pointer\n");

  unregister_kprobe(&k_kallsym);
  pr_info("kprobe at %p unregistered\n", k_kallsym.addr);
  printk(KERN_INFO "ADD returned for stack_trace_save_user : %lx \n", pointer_lookup_name(search_lookup));
  
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
