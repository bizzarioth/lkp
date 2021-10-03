#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <linux/list.h>

static char *int_str;

/* [X1: point 1]
 * Explain following in here.
 * GPL Module license is being set as the module license
 *	Author and Module desciptions are being set
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("[YOUR NAME]");
MODULE_DESCRIPTION("LKP Exercise 4");

/* [X2: point 1]
 * Explain following in here.
 *	Module parameters are being declared as:
 	string input stored as int_str
 	character pointer for integers
 	Access Mod bits being set for READ User permissions for file-owner,group owners and other users.
 */
module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

/* [X3: point 1]
 * Explain following in here.
 *	Sets description of the function argument, int_str in this case
 */
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

/* [X4: point 1]
 * Explain following in here.
 *	Defining the HEAD of a new kernel Linked list structure using mylist 
 */
static LIST_HEAD(mylist);

/* [X5: point 1]
 * Explain following in here.
 *	Defines struct entry with 2 attributes for value stored and pointer to next node
 */
struct entry {
	int val;
	struct list_head list;
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
	if(!List_node)	return -ENOMEM;
	List_node->val = val;
	INIT_LIST_HEAD(&List_node->list);
	list_add_tail(&List_node->list, &mylist);
	return 0;
}

static void test_linked_list(void)
{
	/* [X7: point 10]
	 * Print out value of all entries in mylist.
	 */
	struct list_head *p_head;
	struct entry *lnode;
	list_for_each(p_head, &mylist)
	{
		lnode = list_entry(p_head, struct entry, list);
		printk(KERN_INFO "list detail value: %d \n",lnode->val);
	}
}


static void destroy_linked_list_and_free(void)
{
	/* [X8: point 10]
	 * Free all entries in mylist.
	 */
	struct list_head *p_head, *temp;
	struct entry *node;
	list_for_each_safe(p_head,temp,&mylist)
	{
		node = list_entry(p_head, struct entry, list);
		
		list_del(&node->list);
		
		kfree(node);
	}
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;


	/* [X9: point 1]
	 * Explain following in here.
	 *	Used to Duplicate existing string in memory by allocating memory and then copying the values
	 */
	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	/* [X10: point 1]
	 * Explain following in here.
	 *	Seperates given string using "," as delimiters.
	 */
	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;
		/* [X11: point 1]
		 * Explain following in here.
		 *	Kernel methodcall to parse a string into an integer.
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
		 *	Attempts to create the list node with given val and appends to the linked-list
		 */
		err = store_value(val);
		if (err)
			break;
	}

	/* [X13: point 1]
	 * Explain following in here.
	 *	Clears memory allocated to 'orig' structures.
	 *	error code is also returned here
	 */
	kfree(orig);
	return err;
}

static void run_tests(void)
{
	/* [X14: point 1]
	 * Explain following in here.
	 *	Prints all node values of the linked list in traversion order
	 */
	test_linked_list();
}

static void cleanup(void)
{
	/* [X15: point 1]
	 * Explain following in here.
	 *	This is cleanup method behaviour that destroys the linked list nodes and frees up kernel memory
	 */
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
}

static int __init ex3_init(void)
{
	int err = 0;

	/* [X16: point 1]
	 * Explain following in here.
	 *	Checks value stored in input string.
	 *	Returns if not found
	 */
	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	/* [X17: point 1]
	 * Explain following in here.
	 *	We call the parse_params() method and store the status in err variable.
	 *	This gives us the error code due to any errors and allows us to jump to error handler or even exit the execution
	 */
	err = parse_params();
	if (err)
		goto out;

	/* [X18: point 1]
	 * Explain following in here.
	 *	This runs over the linked list and prints the value of every node
	 */
	run_tests();
out:
	/* [X19: point 1]
	 * Explain following in here.
	 *	This deletes the list and nodes created in memory
	 */
	cleanup();
	return err;
}

static void __exit ex3_exit(void)
{
	/* [X20: point 1]
	 * Explain following in here.
	 *	The exit method
	 * Can perform final operations prior to exit such as cleanup
	 */
	return;
}

/* [X21: point 1]
 * Explain following in here.
 *	This defines the entry point of the module, by calling the  function ex3_init()
 *	It is called when insmod command loads the kernel for execution
  */
module_init(ex3_init);

/* [X22: point 1]
 * Explain following in here.
 *	This defines the exit point of the module, by calling the function ex3_exit() after returning
 */
module_exit(ex3_exit);
