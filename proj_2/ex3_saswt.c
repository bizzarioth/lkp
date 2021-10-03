#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rbtree.h>
#include <linux/xarray.h>
#include <linux/radix-tree.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#define BUFSIZE  1000

static char *int_str;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("[Shashwat Jain]");
MODULE_DESCRIPTION("Project - 2");


module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);


MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

bool last_entry = false;

// Initialize Linked List
static LIST_HEAD(mylist);

// Initialize Hashtable
#define bits 8
static DEFINE_HASHTABLE(myhashtable,bits);

int or = 4;
int bkt = 0;

struct entry {
	int val;
	struct list_head list;
};

struct hEntry {
	int val;
	int key;
	struct hlist_node hList;
};

/* Radix tree */
RADIX_TREE(myRadix, GFP_KERNEL);

/* XARRAY */
DEFINE_XARRAY(myXArray);

/* Red-Black Tree*/
struct rbEntry {
	int val;
	struct rb_node rbNode;
};

struct rb_root rbRoot = RB_ROOT;

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

static int proj2_show(struct seq_file *m, void *v) {
	//seq_printf(m, "Hello proc!\n");
	return 0;
}

static int proj2_open(struct inode *inode, struct  file *file) {
	return single_open(file, proj2_show, NULL);
}

static ssize_t proj2_read(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char buf[BUFSIZE];
	int len=0;
	struct entry *node;
	struct hEntry *hnode;
	struct rb_node *rbTreeNode;
	struct xarray *entry;
	unsigned long int index = 0;
	struct radix_tree_iter iter;
        void **slot;
	//printk( KERN_DEBUG "Read Handler\n");
	if(*ppos > 0 || count < BUFSIZE)
		return 0;
	len += sprintf(buf,"Linked List : ");
	list_for_each_entry(node, &mylist, list)
	{
	 	len += sprintf(buf + len,"%d, ",node->val);
		//printk(KERN_DEBUG "%d\n", node->val);
	}
	len += sprintf(buf + len,"\nHash Table: ");
	hash_for_each(myhashtable, bkt, hnode, hList)
	{
		len += sprintf(buf + len,"%d, ",hnode->val);
	}
	len += sprintf(buf + len, "\nRed-Black Tree: ");
	rbTreeNode = rb_first(&rbRoot);
	while (rbTreeNode)
	{
		len += sprintf(buf + len,"%d, ", rb_entry(rbTreeNode, struct rbEntry, rbNode)->val);
		rbTreeNode = rb_next(rbTreeNode);
	}
	len += sprintf(buf + len, "\nRadix Tree: ");
        radix_tree_for_each_slot(slot, &myRadix, &iter, index)
	{
		len += sprintf(buf + len,"%ld, ", xa_to_value(rcu_access_pointer(*slot)));
	}
	
	len += sprintf(buf + len, "\nXArray: ");
	index = 0;
	xa_for_each(&myXArray, index, entry){
		len += sprintf(buf + len,"%ld, ",xa_to_value(entry));
	}
	len += sprintf(buf + len, "\n");
	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static const struct proc_ops proj2_fops = {
	.proc_open	= proj2_open,
	.proc_read	= proj2_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int store_value(int val)
{
	
	struct entry *node = kmalloc(sizeof(*node), GFP_KERNEL);
	struct hEntry *hnode = kmalloc(sizeof(*hnode), GFP_KERNEL);
	struct rbEntry *rbTreeNode = kmalloc(sizeof(*rbTreeNode), GFP_KERNEL);
	int rbStatus = 0;
	// Check if the memory allocation was successful
	// otherwise return with error -ENOMEM
	if(!node && sizeof(*node))
	{
		return -ENOMEM;
	}
	node->val = val;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &mylist);

	//struct hEntry *hnode = kmalloc(sizeof(*hnode), GFP_KERNEL);
	if(!hnode && sizeof(*hnode))
	{
		return -ENOMEM;
	}
	hnode->val = val;
	hnode->key = val - 1;
	hash_add(myhashtable,&hnode->hList, hnode->key);

	/*RB TREE */
	if(!rbTreeNode && sizeof(*rbTreeNode))
	{
		return -ENOMEM;
        }
	rbTreeNode->val = val;
	rbStatus = rbInsert(&rbRoot, rbTreeNode);

	/* RADIX TREE */
	if(radix_tree_preload(GFP_KERNEL) < 0)
		return -ENOMEM;
	radix_tree_insert(&myRadix, val, xa_mk_value(val));
	radix_tree_preload_end();

	xa_store(&myXArray, val, xa_mk_value(val), GFP_KERNEL);

	return 0;
}

static void test_linked_list(void)
{
	/* [X7: point 10]
	 * Print out value of all entries in mylist.
	 */
	struct entry *node;
	struct hEntry *hnode;
	struct rb_node *rbTreeNode;
	struct xarray *entry;
	struct radix_tree_iter iter;
	void **slot;
	unsigned long int index = 0;

	printk(KERN_INFO "Linked List : ");
	list_for_each_entry(node, &mylist, list)
	{
	 	printk(KERN_CONT "%d, ", node->val);
	}
	printk(KERN_CONT "\n");
	printk(KERN_INFO "Hash Table : ");
	hash_for_each(myhashtable, bkt, hnode, hList)
	{
		printk(KERN_CONT "%d, ", hnode->val);
	}
	printk(KERN_CONT "\n");
	printk(KERN_INFO "Red-Black Tree : ");
	rbTreeNode = rb_first(&rbRoot);
	while (rbTreeNode)
	{
		printk(KERN_CONT "%d, ", rb_entry(rbTreeNode, struct rbEntry, rbNode)->val);
		rbTreeNode = rb_next(rbTreeNode);
	}
	printk(KERN_CONT "\n");
	printk(KERN_INFO "Radix Tree : ");
	radix_tree_for_each_slot(slot, &myRadix, &iter, index){
		printk(KERN_CONT " %ld, ", xa_to_value(rcu_access_pointer(*slot)));
	}
	printk(KERN_CONT "\n");
	printk(KERN_INFO "XArray : ");
	index = 0;
	xa_for_each(&myXArray, index, entry){
		printk(KERN_CONT "%ld, ", xa_to_value(entry));
	}
	printk(KERN_CONT "\n");
}


static void destroy_linked_list_and_free(void)
{
	/* [X8: point 10]
	 * Free all entries in mylist.
	 */
	struct entry *curr_node,*next;
	struct hEntry *curr_hnode;
	struct rb_node *rbTreeNode;
	struct xarray *entry;
	unsigned long int index = 0;
	struct radix_tree_iter iter;
        void **slot;

	//printk(KERN_INFO "Linked List : ");
	list_for_each_entry_safe(curr_node, next, &mylist, list)
	{
		//printk(KERN_CONT "%d", curr_node->val);
		list_del(&curr_node->list);
		kfree(curr_node);
	}
	//printk(KERN_CONT "\n");
	hash_for_each(myhashtable, bkt, curr_hnode, hList)
	{
		//printk(KERN_INFO "Free HT Element with Value: %d\n", curr_hnode->val);
		hash_del(&curr_hnode->hList);
		kfree(curr_hnode);
	}
	rbTreeNode = rb_first(&rbRoot);
	while (rbTreeNode)
	{
		//printk(KERN_INFO "Deleting rb tree node %d\n", rb_entry(rbTreeNode, struct rbEntry, rbNode)->val);
		rb_erase(rbTreeNode, &rbRoot);
		kfree(rbTreeNode);
		rbTreeNode = rb_next(rbTreeNode);
	}

	radix_tree_for_each_slot(slot, &myRadix, &iter, index){
		radix_tree_delete(&myRadix, index);
	}
	index = 0;
	xa_for_each(&myXArray, index, entry){
		//printk(KERN_INFO "Deleting Xarray value: %ld\n", index);
		xa_erase(&myXArray, index);
		xa_release(&myXArray, index);
	}
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;

	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;

		err = kstrtoint(p, 0, &val);
		if (err)
			break;

	
		err = store_value(val);
		if (err)
			break;
	}

	kfree(orig);
	return err;
}

static void run_tests(void)
{
	test_linked_list();
}

static void cleanup(void)
{
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
}

static int __init ex3_init(void)
{
	int err = 0;

	proc_create("proj2", 0, NULL, &proj2_fops);

	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}


	err = parse_params();
	if (err)
		goto out;

	run_tests();
out:
	
	//cleanup();
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

