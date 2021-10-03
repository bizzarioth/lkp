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
#define my_hash_bits 8


static char *int_str;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Mukund]");
MODULE_DESCRIPTION("LKP Exercise 4|PROJ 2");

module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

static LIST_HEAD(mylist);
int bkt=0;

static DEFINE_HASHTABLE(h_tbl, my_hash_bits);
//DECLARE_HASHTABLE(h_tbl, my_hash_bits);

RADIX_TREE(rad_tree, GFP_KERNEL);

struct rb_root rb_tree = RB_ROOT;

DEFINE_XARRAY(myxarr);

struct entry {
    int val;
    struct list_head list;
};

struct rb_type {
    struct rb_node rnode;
    int val;
};

struct hash_node {
    struct hlist_node hnode;
    int val;
    int key;
};

// HASH Table
//static void hash_insert(int val){
//    struct hash_node *h_node;
//    h_node->val=val;
//    h_node->key=val-1;
//    hash_add(h_tbl, &h_node->node, h_node->key );
//}
void hash_iterate(void){
    struct hash_node *cur;
    unsigned long bkt;
    printk(KERN_INFO "\nHashTable:");
    hash_for_each(h_tbl, bkt, cur, hnode) {
        printk(KERN_INFO "val= %d", cur->val);
    }
}
void hash_cleaner(void){
    struct hash_node *cur;
    unsigned long bkt;
    hash_for_each(h_tbl, bkt, cur, hnode) {
        hash_del(&cur->hnode);
        kfree(cur);
    }    
}
//RB Tree insert and Iterate
int rb_insert(struct rb_root *root, struct rb_type *entry){
    struct rb_node **new= &(root->rb_node), *parent = NULL;
    //where insert
    while(*new) {
        struct rb_type *this = container_of(*new, struct rb_type, rnode);
        //int result = strcmp(vals->keystring, this->keystring);
        parent = *new;
        if (entry->val < this->val)
            new = &((*new)->rb_left);
        else if (entry->val > this->val)
            new = &((*new)->rb_right);
        else
            return -1;
    }
    /* Add new node and rebalance tree. */
    rb_link_node(&entry->rnode, parent, new);
    rb_insert_color(&entry->rnode, root);
    return 0;
}
void rb_iterate(void){
    struct rb_node *tnode;
    tnode = rb_first(&rb_tree);
    printk(KERN_INFO "\nRED_BLACK Tree::");
    while(tnode){
        printk(KERN_INFO "val=%d ", rb_entry(tnode, struct rb_type, rnode)->val);
        tnode = rb_next(tnode);
    }
}
void rb_cleaner(void){
    struct rb_node *tnode;
    tnode = rb_first(&rb_tree);
    while(tnode){
        rb_erase(tnode, &rb_tree);
        kfree(tnode);
        tnode = rb_next(tnode);
    }   
}
//RADIX TREE
int rad_insert(int val){
    
    if(radix_tree_preload(GFP_KERNEL)<0) return -ENOMEM;
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< HEAD
    radix_tree_insert(&rad_tree, val-1, xa_mk_value(val));
=======
    radix_tree_insert(&rad_tree, val, xa_mk_value(val));
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
=======
    radix_tree_insert(&rad_tree, val, xa_mk_value(val));
>>>>>>> Stashed changes
=======
    radix_tree_insert(&rad_tree, val, xa_mk_value(val));
>>>>>>> Stashed changes
=======
    radix_tree_insert(&rad_tree, val, xa_mk_value(val));
>>>>>>> Stashed changes
    radix_tree_preload_end();
    return 0;
}
void rad_iterate(void){
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< HEAD
	
	unsigned long i=0;
	void *	arr = kmalloc(10*sizeof(void*), GFP_KERNEL);
	radix_tree_gang_lookup(&rad_tree, &arr, i,10);
	i=0;
	printk(KERN_INFO "\nRADIX : ");
	for(i=0;i<5;i++)     printk(KERN_INFO "%d, ",*(arr+i));
	printk(KERN_INFO "\n");
=======
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
=======
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
}
void rad_cleaner(void){

}

//XArray

void xa_iter(void){
    unsigned long bkt=0;
    struct xarray *entry;
    printk(KERN_INFO "\nXARRAY::");
    xa_for_each(&myxarr, bkt, entry){
        printk(KERN_INFO " %ld, ",xa_to_value(entry));
    }
}
void xa_cleaner(void){
    unsigned long bkt=0;
    struct xarray *entry;
    xa_for_each(&myxarr, bkt, entry){
        xa_erase(&myxarr, bkt);
        xa_release(&myxarr, bkt);
    }
}

static int proc_show(struct seq_file *m, void *v){
    //seq_printf(m, "Hello proj2!\n");
    return 0;
}
static int proc_opener(struct inode *in, struct file *f){
    return single_open(f, proc_show, NULL);
}
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos){
    char buf[BUFSIZE];
    int len=0;
    struct entry *ln;
    unsigned long int i=0;
    struct hash_node *cur;
    struct rb_node *rt;
    struct xarray *entry;
    
    if(*ppos > 0 || count < BUFSIZE)
        return 0;
    
    len += sprintf(buf,"\nLinked List : ");
    list_for_each_entry(ln, &mylist, list)
    {
        len += sprintf(buf + len,"%d, ",ln->val);
        //printk(KERN_DEBUG "%d\n", node->val);
    }
    len += sprintf(buf+len,"\nHASHTABLE : ");
    
    hash_for_each(h_tbl, bkt, cur, hnode) {
        len += sprintf(buf + len,"%d, ",cur->val);
    }
    
    len+= sprintf(buf+len, "\nRed_Black Tree : ");
    rt=rb_first(&rb_tree);
    while(rt){
        len+=sprintf(buf+len, "%d, ", rb_entry(rt, struct rb_type, rnode)->val);
        rt=rb_next(rt);
    }

    len+=sprintf(buf+len, "\nXArray : ");
    i=0;
    xa_for_each(&myxarr, i, entry){
        len += sprintf(buf + len,"%ld, ",xa_to_value(entry));
    }
    
    len += sprintf(buf + len, "\n");

    if(copy_to_user(ubuf,buf,len)) return -EFAULT;

    *ppos = len;
    return len;
}

static const struct proc_ops myops = 
{
    //.owner = THIS_MODULE,
    .proc_open = proc_opener,
    .proc_read = myread,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

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
    struct hash_node *hn=kmalloc(sizeof(*hn),GFP_KERNEL);
    struct rb_type *rt=kmalloc(sizeof(*rt),GFP_KERNEL);

    if(!List_node && sizeof(*List_node))  return -ENOMEM;
    List_node->val = val;
    INIT_LIST_HEAD(&List_node->list);
    list_add_tail(&List_node->list, &mylist);

    if(!hn && sizeof(*hn)) return -ENOMEM;
    //hash_insert(val);
    hn->val=val;
    hn->key=val-1;
    hash_add(h_tbl, &hn->hnode, hn->key );

    if(!rt && sizeof(*rt)) return -ENOMEM;
    rt->val=val;
    rb_insert(&rb_tree,rt);
    
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< HEAD
    rad_insert(val);
=======
    //rad_insert(val);
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
=======
    //rad_insert(val);
>>>>>>> Stashed changes
=======
    //rad_insert(val);
>>>>>>> Stashed changes
=======
    //rad_insert(val);
>>>>>>> Stashed changes
    xa_store(&myxarr, val, xa_mk_value(val), GFP_KERNEL);
    return 0;
}
static void test_linked_list(void){
    //Printer
    struct list_head *p_head;
    struct entry *lnode;
    printk(KERN_INFO "Linked List : ");
    list_for_each(p_head, &mylist)
    {
        lnode = list_entry(p_head, struct entry, list);
        printk(KERN_INFO "%d, ",lnode->val);
    }
    hash_iterate();
    rb_iterate();
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< HEAD
    rad_iterate();
=======
    //rad_iterate();
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
=======
    //rad_iterate();
>>>>>>> Stashed changes
=======
    //rad_iterate();
>>>>>>> Stashed changes
=======
    //rad_iterate();
>>>>>>> Stashed changes
    xa_iter();
    printk(KERN_INFO "\n");
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
    //rad_cleaner();
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

}

static int __init ex3_init(void)
{
    int err = 0;
    proc_create("proj2", 0, NULL, &myops);

    if (!int_str) {
        printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
        return -1;
    }
    
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
    return err;
}

static void __exit ex3_exit(void)
{
    cleanup();
    remove_proc_entry("proj2", NULL);
    return;
}

module_init(ex3_init);

module_exit(ex3_exit);
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< Updated upstream
<<<<<<< HEAD

=======
>>>>>>> 6a9c1ec7161423cc8a570b10b2766bdad15b1cea
=======
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
=======
>>>>>>> Stashed changes
