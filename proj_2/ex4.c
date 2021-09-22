#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/moduleparam.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>
#include <linux/types.h>

#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/xarray.h>

#define BUFSIZE  1000
#define HASH_BITS 8


static char *int_str;
static struct proc_dir_entry *ent;
char buf[BUFSIZE];

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund]");
MODULE_DESCRIPTION("LKP Exercise 4|PROJ 2");

module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

static LIST_HEAD(mylist);

static DEFINE_HASHTABLE(h_tbl, HASH_BITS);
DECLARE_HASHTABLE(h_tbl, HASH_BITS);

RADIX_TREE(rad_tree, GFP_KERNEL);

struct rb_root rb_tree = RB_ROOT;

DEFINE_XARRAY(myxarr);

struct entry {
    int val;
    struct list_head list;
};

struct rb_type {
    struct rb_node node;
    int val;
};

struct hash_node {
    struct hlist_node node;
    int val;
    int key;
};

struct rad_entry{
    int val;
};
struct x_node{
    int val;
}

// HASH Table
static void hash_insert(int val){
    struct hash_node *h_node;
    h_node->val=val;
    h_node->key=val-1;
    hash_add(h_tbl, &h_node->node, h_node->key );
}
void hash_iterate(){
    struct hash_node *cur;
    unsigned long bkt;
    printk(KERN_INFO "\nHashTable:");
    hash_for_each(h_tbl, bkt, cur, node) {
        printk(KERN_INFO "val= %d", cur->val);
    }
}
void hash_cleaner(){
    struct hash_node *cur;
    unsigned long bkt;
    hash_for_each(h_tbl, bkt, cur, node) {
        hash_del(cur->node);
        kfree(cur);
    }    
}
//RB Tree insert and Iterate
int rb_insert(struct rb_root *root, struct rb_type *entry){
    struct rb_node **new= &(root->rb_node), *par = NULL;
    //where insert
    while(*new) {
        struct rb_type *this = container_of(*new, struct rb_type, node);
        int result = strcmp(vals->keystring, this->keystring);
        parent = *new;
        if (result < 0)
            new = &((*new)->rb_left);
        else if (result > 0)
            new = &((*new)->rb_right);
        else
            return FALSE;
    }
    /* Add new node and rebalance tree. */
    rb_link_node(&vals->node, parent, new);
    rb_insert_color(&vals->node, root);
    return TRUE;
}
void rb_iterate(){
    struct rb_node *node;
    node = rb_first(&rb_tree);
    printk(KERN_INFO "\nRED_BLACK Tree::");
    while(node){
        printk(KERN_INFO "val=%d ", rb_entry(node, struct rb_type, node)->key);
        node = rb_next(node)
    }
}
void rb_cleaner(){
    struct rb_node *node;
    node = rb_first(&rb_tree);
    while(node){
        rb_erase(node, &rb_tree);
        kfree(node);
        node = rb_next(node)
    }   
}
//RADIX TREE
void rad_insert(int val){
    
    if(radix_tree_preload(GFP_KERNEL)<0) return -ENOMEM;
    radix_tree_insert(&rad_tree, val, xa_mk_value(val));
    radix_tree_preload_end();
    return 0;
}
void rad_iterate(){
}
void rad_cleaner(){

}

//XArray

void xa_iter(){
    unsigned long bkt=0;
    struct xarray *entry;
    printk(KERN_INFO "\nXARRAY::");
    xa_for_each(&myxarr, bkt, entry){
        printk(KERN_INFO " %ld, ",xa_to_value(entry));
    }
}
void xa_cleaner(){
    unsigned long bkt=0;
    struct xarray *entry;
    xa_for_each(&myxarr, bkt, entry){
        xa_erase(&myxarr, bkt);
        xa_release(&myxarr, bkt);
    }
}
static const struct proc_ops myops = 
{
    //.owner = THIS_MODULE,
    .proc_read = myread,
    .proc_open = proc_opener,
    .proc_release = single_release,
};

static int proc_show(struct seq_file *m, void *v){
    seq_printf(m, "Hello proj2!\n");
    return 0
}
static int proc_opener(struct inode *in, struct file *f){
    return single_open(f, proc_show, NULL);
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos){
    char buf[BUFSIZE];
    int len=0,i=0;
    struct entry *ln;
    unsigned long bkt;
    if(*ppos > 0 || count < BUFSIZE)
        return 0;
    len += sprintf(buf,"\nLinked List : ");
    list_for_each_entry(node, &mylist, list)
    {
        len += sprintf(buf + len,"%d, ",node->val);
        //printk(KERN_DEBUG "%d\n", node->val);
    }
    len += sprintf(buf,"\nHASHTABLE : ");
    struct hash_node *cur;
    hash_for_each(h_tbl, bkt, cur, node) {
        len += sprintf(buf + len,"%d, ",cur->val);
    }
    
    len+= sprintf(buf, "\nRed_Black Tree : ");
    struct rb_node *rt;
    rt=rb_first(&rb_tree);
    while(rt){
        len+=sprintf(buf+len, "%d, ", rb_entry(rt, struct rb_type, node)->key);
        rt=rb_next(rt);
    }

    len+=sprintf(buf+len, "\nXArray : ");
    i=0;
    struct xarray *entry;
    xa_for_each(&myxarr, i, entry){
        len += sprintf(buf + len,"%ld, ",xa_to_value(entry));
    }
    len += sprintf(buf + len, "\n");

    if(copy_to_user(ubuf,buf,len)) return -EFAULT;

    *ppos = len;
    return len;
}

static int simple_init(void)
{
    ent=proc_create("proj2",0,NULL,&myops);
    return 0;
}

static void simple_cleanup(void)
{
    proc_remove(ent);
}

static int store_value(int val)
{
    /* [X6: point 10]
     * Allocate a struct entry of which val is val
     * and add it to the tail of mylist.
     * Return 0 if everything is successful.
     * Otherwise (e.g., memory allocation failure),
     * return corresponding error code in error.h (e.g., -ENOMEM).
     */
    struct entry *List_node = kmalloc(sizeof(*List_node), GFP_KERNEL);
    if(!List_node && sizeof(*List_node))  return -ENOMEM;
    List_node->val = val;
    INIT_LIST_HEAD(&List_node->list);
    list_add_tail(&List_node->list, &mylist);

    struct hash_node *hn=kmalloc(sizeof(*hn),GFP_KERNEL);
    
    if(!hn && sizeof(*hn)) return -ENOMEM;
    hash_insert(val);
    struct rb_type *rt=kmalloc(sizeof(*rt),GFP_KERNEL);
    if(!rt && sizeof(*rt)) return -ENOMEM;
    rt->val=val;
    rb_insert(&rb_tree,rt);
    
    rad_insert(val);
    xa_store(&myxarr, val, xa_mk_valu(val), GFP_KERNEL);
    return 0;
}
static void test_linked_list(void){
    //Printer
    struct list_head *p_head;
    struct entry *lnode;
    list_for_each(p_head, &mylist)
    {
        lnode = list_entry(p_head, struct entry, list);
        printk(KERN_INFO "list detail value: %d \n",lnode->val);
    }
    hash_iterate();
    rb_iterate();
    rad_iterate();
    xa_iter();
}

static void destroy_linked_list_and_free(void){
    struct list_head *p_head, *temp;
    struct entry *node;
    list_for_each_safe(p_head,temp,&mylist)
    {
        node = list_entry(p_head, struct entry, list);
        list_del(&node->list);
        kfree(node);
    }
    hash_cleaner();
    rb_cleaner();
    rad_cleaner();
    xa_cleaner();
}
static int parse_params(void)
{
    int val, err = 0;
    char *p, *orig, *params;


    /* [X9: point 1]
     * Explain following in here.
     *  Used to Duplicate existing string in memory by allocating memory and then copying the values
     */
    params = kstrdup(int_str, GFP_KERNEL);
    if (!params)
        return -ENOMEM;
    orig = params;

    /* [X10: point 1]
     * Explain following in here.
     *  Seperates given string using "," as delimiters.
     */
    while ((p = strsep(&params, ",")) != NULL) {
        if (!*p)
            continue;
        /* [X11: point 1]
         * Explain following in here.
         *  Kernel methodcall to parse a string into an integer.
         * Specified arguments are -
         NULL terminated string pointer
         Base Index
         Pointer to store result
         */
        err = kstrtoint(p, 0, &val);
        if (err)
            break;

        /* [X12: point 1]
         * Explain following in here.
         *  Attempts to create the list node with given val and appends to the linked-list
         */
        err = store_value(val);
        if (err)
            break;
    }

    /* [X13: point 1]
     * Explain following in here.
     *  Clears memory allocated to 'orig' structures.
     *  error code is also returned here
     */
    kfree(orig);
    return err;
}
static void run_tests(void)
{
    /* [X14: point 1]
     * Explain following in here.
     *  Prints all node values of the linked list in traversion order
     */
    test_linked_list();
}

static void cleanup(void)
{
    /* [X15: point 1]
     * Explain following in here.
     *  This is cleanup method behaviour that destroys the linked list nodes and frees up kernel memory
     */
    printk(KERN_INFO "\nCleaning up...\n");

    destroy_linked_list_and_free();
    simple_cleanup();
}

static int __init ex3_init(void)
{
    int err = 0;

    if (!int_str) {
        printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
        return -1;
    }
    err=simple_init();
    /* [X17: point 1]
     * Explain following in here.
     *  We call the parse_params() method and store the status in err variable.
     *  This gives us the error code due to any errors and allows us to jump to error handler or even exit the execution
     */
    err = parse_params();
    if (err)
        goto out;

    /* [X18: point 1]
     * Explain following in here.
     *  This runs over the linked list and prints the value of every node
     */
    run_tests();
out:
    /* [X19: point 1]
     * Explain following in here.
     *  This deletes the list and nodes created in memory
     */
    cleanup();
    return err;
}

static void __exit ex3_exit(void)
{
    return;
}
module_init(ex3_init);
module_exit(ex3_exit);
