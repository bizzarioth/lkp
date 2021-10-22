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
#include <linux/rbtree.h>

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
static int counter=0;
//SPINLOCK
DEFINE_SPINLOCK(mySpin_lock);
static unsigned long long time_start;
unsigned long long time_fin;

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
  uint32_t trace_hash;
  int count_shed;
  int pid;
  unsigned long long htimer;
  unsigned long stack_dump[mTrace];
  int len_trace;
  struct hlist_node hList;
};

/* Red-Black Tree*/
struct rbEntry {
  //runtime is stored in val
  unsigned long long val;
  unsigned long stack_dump[mTrace];
  uint32_t trace_hash;
  int len_trace;
  struct rb_node rbNode;
};

struct rb_root rbRoot = RB_ROOT;
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
static int hash_inc_jhash(uint32_t trace_hash, int pid, int len_trace, unsigned long *dump){
  /*
  Function to Insert/Increment Hash table Node with key = JHash(Stack_Trace)
    Debug: Takes jHash of trace and stores it
  */
  int i;
  struct hEntry *tnode;
  struct hEntry *hnode = kmalloc(sizeof(*hnode), GFP_ATOMIC);
  if(!hnode && sizeof(*hnode))
  {
    return -ENOMEM;
  }
  //search pid(key)
  //hash_for_each(myhashtable, bkt, tnode, hList)
  hash_for_each_possible(myhashtable, tnode, hList, trace_hash)
  {
    //if(pid==tnode->key){
    if(trace_hash == tnode->trace_hash){
      //found : increment
      tnode->count_shed++;
      hnode->htimer += time_fin - time_start;
      return 0;
      }
  }

  //create Node if it doesnot exist
  hnode->trace_hash = trace_hash;
  hnode->count_shed = 1;
  hnode->pid = pid;
  hnode->len_trace = len_trace;
  
  i=0;
  while(i < hnode->len_trace){
  	hnode->stack_dump[i] = dump[i];
  	i++;
  }
  hnode->htimer = time_fin - time_start;
  hash_add(myhashtable,&hnode->hList, hnode->trace_hash);
  return 0;
}

int hash_inc_pid(int pid, u32 trace_hash){
  /*
  Project 3 Part 1
  Function to Insert/Increment Hash table Node
    Key = pid
  */
  struct hEntry *tnode;
  struct hEntry *hnode = kmalloc(sizeof(*hnode), GFP_ATOMIC);
  if(!hnode && sizeof(*hnode))
  {
    return -ENOMEM;
  }
  //search pid(key)
  hash_for_each(myhashtable, bkt, tnode, hList)
  {
    if(pid==tnode->pid){
      //found : increment
      tnode->count_shed++;
      return 0;
      }
  }
  //create Node if it doesnot exist
  hnode->pid = pid;
  hnode->count_shed = 1;
  hnode->trace_hash= trace_hash;
  hash_add(myhashtable,&hnode->hList, hnode->pid);
  return 0;
}
//RB Tree inserter
/*Project 3 Part 2
  - RbTree default insert function
  - RbTree function to store node with new runtime for a jHash
*/
int rbInsert(struct rb_root *root, struct rbEntry *data){
  
  struct rb_node **new = &(root->rb_node), *parent = NULL;

  /* Figure out where to put new node */
  while (*new) {
    struct rbEntry *this = container_of(*new, struct rbEntry, rbNode);

    parent = *new;
    if (data->val < this->val)
      new = &((*new)->rb_left);
    else if (data->val > this->val)
      new = &((*new)->rb_right);
    else
      return -1;
  }

  /* Add new node and rebalance tree. */
  rb_link_node(&data->rbNode, parent, new);
  rb_insert_color(&data->rbNode, root);

  return 0;
}
int rb_inc_timer(uint32_t jhashkey, int len_trace, unsigned long *dump){
  /*
  Delete node found with existing jhashkey
  Insert node with new time val
  @jhashkey : Node key
  @len_trace : Length of trace dump
  @dump : Trace dump pointer

  */
  struct rbEntry *rbTreeNode = kmalloc(sizeof(*rbTreeNode), GFP_ATOMIC);
  //int rbStatus = 0;
  struct rb_node *temp,*curnode;
  struct rbEntry *rbelement;
  unsigned long long prev_timer=0;
  int i;
  
  curnode=rb_first(&rbRoot);
  //Traverse RbTree for existing jHashkey
  while(curnode){
    rbelement = rb_entry(curnode, struct rbEntry, rbNode);
    temp = curnode;
    //printk(KERN_INFO "Current RB Entry with %u",rbelement->trace_hash);
    if(rbelement->trace_hash == jhashkey){
      //Store previous run time
      prev_timer = rbelement->val;
      //Remove existing 
      //printk(KERN_INFO "Removing RB Entry with %u",rbelement->trace_hash);
      rb_erase(curnode, &rbRoot);
      kfree(rbelement);
      break;
    }
    curnode= rb_next(temp);
  }
  if(!rbTreeNode && sizeof(*rbTreeNode))
  {
    return -ENOMEM;
  }//create Node
  rbTreeNode->val = prev_timer + time_fin - time_start;
  rbTreeNode->len_trace = len_trace;
  rbTreeNode->trace_hash = jhashkey;
  i=0;
  while(i < len_trace){
    rbTreeNode->stack_dump[i] = dump[i];
    i++;
  }
  //--
  rbInsert(&rbRoot, rbTreeNode);
  return 0;
}

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
  unsigned long stack_storer[mTrace],flags;
  char pbuff[256];
  int len_trace;
  u32 hashKey;
  struct task_struct * my_task;
  int kernel_task_flag=0;
/*
  #ifdef CONFIG_X86
    pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
      p->symbol_name, p->addr, regs->ip, regs->flags);
  #endif
*/
  /* A dump_stack() here will give a stack backtrace */
//  printk(KERN_INFO "KM PID! %d\n RSI addr: %lx\n",my_task->pid, regs->si);

  if((regs->si)==0) return 0;

  my_task = (struct task_struct *)regs->si;
  /*
  Use stack_trace_save function for a kernel task
  Use save_stack_trace_user function for a user task
  -----> use instead stack_trace_save_user
  mm==NULL means kernel task
  */
//  printk(KERN_INFO "KM PID: %d task_struct->mm = %pB",my_task->pid, my_task->mm);
  if(my_task->mm){
    //USER thread
    //Get save_user() ADDRESS
    pointer_save_user = (func_user*)pointer_lookup_name(search_lookup);
    if(pointer_save_user == NULL){
    	printk(KERN_INFO "KM ERROR: Did Not Find stack_trace_save_user\n");
    	return -1;
    }
//    printk(KERN_INFO "USER PID\n");
    len_trace = pointer_save_user(stack_storer, mTrace);
//    printk(KERN_INFO "USER PID Stack Trace %d entries\n",len_trace);
    stack_trace_print(stack_storer,len_trace,5);
    hashKey= jhash(stack_storer ,len_trace*sizeof(unsigned long) ,JHASH_INITVAL);
//    printk(KERN_INFO "USER jhash::0x%x\n", hashKey);
    kernel_task_flag=0;

  }else{
    //kernel thread
    len_trace = stack_trace_save(stack_storer,mTrace,0);
//    printk(KERN_INFO "KERN STACK Trace\n");
    stack_trace_print(stack_storer,len_trace,5);
    hashKey= jhash(stack_storer ,len_trace*sizeof(unsigned long) ,JHASH_INITVAL);
//    printk(KERN_INFO "jhash::0x%x\n", hashKey);
    kernel_task_flag=1;
  }
  spin_lock_irqsave(&mySpin_lock,flags);
  time_fin = rdtsc();
  //time_fin-=time_start;
  //hash_inc_pid((int)my_task->pid, u32 hashKey);
  //hash_inc_jhash(hashKey, (int)my_task->pid, len_trace, stack_storer);
  if(kernel_task_flag) rb_inc_timer(hashKey,len_trace, stack_storer);
  
  spin_unlock_irqrestore(&mySpin_lock,flags);

  time_start = rdtsc();

  counter = my_task->pid;
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

  int i;
  int rb_count=20;
  char buf[mBUFSIZE];
  struct hEntry *hnode;
  struct rbEntry *myrb;
  struct rb_node *node;
  
  node = rb_last(&rbRoot);
  seq_printf(m ,"RB Tree : Most scheduled traces-\n");
  while(node && rb_count>0){
    myrb= rb_entry(node, struct rbEntry, rbNode);
    node = rb_prev(node);
    seq_printf(m ,"------------Stack Trace------------\n");
    seq_printf(m ,"Scheduled Task Rank::\t%d\n",(21-rb_count));
    seq_printf(m ,"\t Thread jHash:\t%u\n",myrb->trace_hash);
    i = 0;
    while(i < myrb->len_trace)
    {
      seq_printf(m ,"%pS\n", (void *)myrb->stack_dump[i]);
      i++;
    }
    //seq_printf(m ,"Count\t%d\t|\tJHash\t%x\n", myrb->count_shed, myrb->trace_hash);
    seq_printf(m ,"\tRun Time on CPU::\t%llu\trdtsc_ticks\n", myrb->val );
    seq_printf(m ,"-----------------------------------\n");
    rb_count--;
  }
  seq_printf(m ,"/----END--OF--RedBlackTree------------------------/-\n\n");
  
  seq_printf(m, "HASHTABLE: Stack Counter and Trace\n");
  hash_for_each(myhashtable, bkt, hnode, hList){
  	seq_printf(m ,"------------Stack Trace------------\n");
		i = 0;
		while(i < hnode->len_trace)
		{
			seq_printf(m ,"%pS\n", (void *)hnode->stack_dump[i]);
			i++;
		}
		//seq_printf(m ,"Count\t%d\t|PID\t%d|JHash\t%x\n", hnode->count_shed, hnode->pid,hnode->trace_hash);
		seq_printf(m ,"Count\t%d\t|\tJHash\t%x\n", hnode->count_shed, hnode->trace_hash);
    seq_printf(m ,"\tRun Time::\t%llu\trdtsc_ticks\n", hnode->htimer );
    seq_printf(m ,"-----------------------------------\n\n");
	}
  

  return 0;
}

static int proc_opener(struct inode *in, struct file *f){
  return single_open(f, proc_show, NULL);
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos){

  int len=0;
  char buf[mBUFSIZE];
  struct hEntry *hnode;
  if(*ppos > 0 || count < mBUFSIZE) return 0;

  len += sprintf(buf,"Hash Table: \n");
  //len += sprintf(buf," PID\t|\tTimes Called\t|\tJHash\n");
  len += sprintf(buf," jHash\t|\tTimes Called\t|\tPID1\n");
  
  hash_for_each(myhashtable, bkt, hnode, hList)
  {
    //len += sprintf(buf + len," %d\t|\t%d\t|\t%x\t|\t%d\n ",hnode->key,hnode->count_shed, hnode->trace_hash, hnode->chk);
    len += sprintf(buf + len,"	%d\t|\t%d\t|\t%u\n",hnode->pid ,hnode->count_shed, hnode->trace_hash);
  }

  len += sprintf(buf + len, "\n");

  if(copy_to_user(ubuf,buf,len)) return -EFAULT;

  *ppos = len;
  return len;
}

static const struct proc_ops myops = 
{
  .proc_open = proc_opener,
  .proc_read = seq_read,
  //.proc_read = myread,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int kprobe_init(void){
  int ret,ret_kallsym;
  kproc_open.pre_handler = handler_pre;
  kproc_open.post_handler = handler_post;

  ret_kallsym = register_kprobe(&k_kallsym);
  if (ret_kallsym < 0) {
    pr_err("register k_kallsym failed, returned %d\n", ret_kallsym);
    return ret_kallsym;
  }
//  pr_info("Planted k_kallsym probe at %p\n", k_kallsym.addr);
  /* Get pointers to lookup and save_user*/
  pointer_lookup_name = (func_lookup*)k_kallsym.addr;
  if(pointer_lookup_name == NULL){
//    printk(KERN_INFO "KM ERROR: Did Not Find kallsyms_lookup_name\n");
    return -1;
  }

//  printk(KERN_INFO "CALL lookup pointer\n");
//  printk(KERN_INFO "ADD returned for stack_trace_save_user : %lx \n", pointer_lookup_name(search_lookup));
  
  ret = register_kprobe(&kproc_open);
  if (ret < 0) {
    pr_err("register_kprobe failed, returned %d\n", ret);
    return ret;
  }
//  pr_info("Planted kprobe at %p\n", kproc_open.addr);

  return 0;
}

static int __init proj_init(void) {
  int err=0;
  time_start = rdtsc();
  proc_create("perftop", 0, NULL, &myops);

  err+=kprobe_init();
  if(err) return err;
  return 0;
}

static void __exit proj_exit(void) {
  
  struct hEntry *tnode;
  struct rb_node *node, *tempN;
  struct rbEntry *element;
  //Delete RBTree memory
  node = rb_first(&rbRoot);
  while(node){
    element = rb_entry(node, struct rbEntry, rbNode); 
    tempN = node;
    rb_erase(node, &rbRoot);
    node = rb_next(tempN);
    kfree(element); 
  }
  //Delete HashTable memory
  hash_for_each(myhashtable, bkt, tnode, hList)
  {
    hash_del(&tnode->hList);
		kfree(tnode);
  }

  remove_proc_entry("perftop", NULL);

  unregister_kprobe(&kproc_open);
//  pr_info("kprobe at %p unregistered\n", kproc_open.addr);

  unregister_kprobe(&k_kallsym);
//  pr_info("kprobe at %p unregistered\n", k_kallsym.addr);

  return;
}

module_init(proj_init);
module_exit(proj_exit);
