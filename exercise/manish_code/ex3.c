#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
static char *int_str;

/* [X1: point 1]
 * Explain following in here.
 * In the following three lines we are defining the Module Licence to be under the GPL license, 
 * That the author of this module is the person mentioned in the second line 
 * and giving a description for what the module does in line following that. Basically we are 
 * giving the basic description for the modile, like metadata.
 */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("[YOUR NAME]");
MODULE_DESCRIPTION("LKP Exercise 4");

/* [X2: point 1]
 * Explain following in here.
 * We are declaring what the module parameters that are going to be used, the string being the string
 * charp is a character pointer for the integers
 * S_IRUSR S_IRGRP S_IROTH are Mode bits for access permissions, which denote the following permissions: 
 * S_IRUSR: Read permission bit for the owner of the file. On many systems this bit is 0400.
 * S_IRGRP: Read permission bit for the group owner of the file. Usually 040.
 * S_IROTH: Read permission bit for other users. Usually 04.
 */
module_param(int_str, charp, S_IRUSR | S_IRGRP | S_IROTH);

/* [X3: point 1]
 * Explain following in here.
 * We are setting a description for the parameter that we are accepting, as this module is supposed to take
 * an imput string that is a comma seperated list of integers, that is what we set as description. 
 */
MODULE_PARM_DESC(int_str, "A comma-separated list of integers");

/* [X4: point 1]
 * Explain following in here.
 * We defined a new list head, a kernel linked list data structure head, mylist whose head is pointing to * itself
 */
static LIST_HEAD(mylist);

/* [X5: point 1]
 * Explain following in here.
 * We are defining a structure that has two parameters, a list_head data type parameter to point the 
 * previous and next nodes and an integer val to store the value of the list
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
	 //entry newEntry = new entry(); entry will be the nodeElement 
	 // value. 
	 //entry.val->val
	 //entry.head->prev node
	 //entry.tail->next node/head node
	 // check validity of nodes. 
	 
		struct entry *nodeElement = kmalloc(sizeof(*nodeElement), GFP_KERNEL);
		if(!nodeElement){
			return -ENOMEM;
		}
		nodeElement->val = val;
		INIT_LIST_HEAD(&nodeElement->list);
		list_add_tail(&nodeElement->list, &mylist);
		return 0;
		
}

static void test_linked_list(void)
{
	/* [X7: point 10]
	 * Print out value of all entries in mylist.
	 */
	 //loop over the list
	 //print the elements
	 struct list_head *nodeLoc;
	 struct entry *nodeElement;
	 list_for_each(nodeLoc, &mylist) {
        /* nodeElement points to the structure in which the list is embedded */
        nodeElement = list_entry(nodeLoc, struct entry, list);
		printk(KERN_INFO "list detail value: %d \n",nodeElement->val);
	}
	 
	 
}


static void destroy_linked_list_and_free(void)
{
	/* [X8: point 10]
	 * Free all entries in mylist.
	 */
		struct list_head *nodeLoc, *tempLoc;
		struct entry *nodeElement;
		list_for_each_safe(nodeLoc,tempLoc,&mylist) {
		 nodeElement = list_entry(nodeLoc, struct entry, list);
		//printk(KERN_INFO "DELETING ELEMENT: %d\n",nodeElement->val);
		list_del(&nodeElement->list);
		//printk(KERN_INFO "DELETING ELEMENT2: %d\n",nodeElement->val);
		kfree(nodeElement);
		//printk(KERN_INFO "DELETING ELEMENT3: %d\n",nodeElement->val);		
	 }
}


static int parse_params(void)
{
	int val, err = 0;
	char *p, *orig, *params;


	/* [X9: point 1]
	 * Explain following in here.
	 * kstrdup is a kernel function that copies an existing 
	 * string into kernel memory space after allocating space 
	 * for it. The GFP mask used during the internal kmalloc 
	 * call in this case is GFP_KERNEL
	 */
	params = kstrdup(int_str, GFP_KERNEL);
	if (!params)
		return -ENOMEM;
	orig = params;

	/* [X10: point 1]
	 * Explain following in here.
	 * We are splitting the input string on ',' using strsep 
	 * function, the string(params) is in the kernel memory 
	 * space and ',' is the delimitter and looping over it. 
 	 */
	while ((p = strsep(&params, ",")) != NULL) {
		if (!*p)
			continue;
		/* [X11: point 1]
		 * Explain following in here.
		 * kernel function to convert a string to an integer, the
		 * second parameter is the base to which the first null 
		 * terminated string parameter is converted and the 
		 * third parameter is where the result is written. 
		 * Returns 0 on success, 
		 * -ERANGE on overflow and -EINVAL on parsing error.
		 */
		err = kstrtoint(p, 0, &val);
		if (err)
			break;

		/* [X12: point 1]
		 * Explain following in here.
		 * calling the store_value function to create a new 
		 * struct node with val as val and add it to the linked 
		 * list
		 */
		err = store_value(val);
		if (err)
			break;
	}

	/* [X13: point 1]
	 * Explain following in here.
	 * Here we are freeing up the memory space allocated to 
	 * orig by kmalloc and returning the err code.
	 */
	kfree(orig);
	return err;
}

static void run_tests(void)
{
	/* [X14: point 1]
	 * Explain following in here.
	 * Here we are traversing the linux linked list and 
	 * printing the element's value as we traverse them. 
	 */
	test_linked_list();
}

static void cleanup(void)
{
	/* [X15: point 1]
	 * Explain following in here.
	 * we are calling the destroy_linked_list_and_free which 
	 * deletes individual nodes and frees up the memory allocated 
	 * to them using kmalloc, kfree and list_del
	 */
	printk(KERN_INFO "\nCleaning up...\n");

	destroy_linked_list_and_free();
}

static int __init ex3_init(void)
{
	int err = 0;

	/* [X16: point 1]
	 * Explain following in here.
	 * Here we are checking if the input string passed has a value
	 * in it. If it doesn't we throw an error. 
	 */
	if (!int_str) {
		printk(KERN_INFO "Missing \'int_str\' parameter, exiting\n");
		return -1;
	}

	/* [X17: point 1]
	 * Explain following in here.
	 * Here we are calling the parse_params method and checking 
	 * whether we are able to successfully parse the parameters and 
	 * store them. Incase of any error, we are returning the 
	 * negative error code to satisfy the below if condition and 
	 * jump to the location "out" in the code.  
	 */
	err = parse_params();
	if (err)
		goto out;

	/* [X18: point 1]
	 * Explain following in here.
	 * Here we are iterating over the linked list and printing the 
	 * value stored within each node 
	 */
	run_tests();
out:
	/* [X19: point 1]
	 * Explain following in here.
	 * Clean up deletes the nodes and the whole list and frees up 
	 * the memory after the testing and storage of inputs is complete.
	 */
	cleanup();
	return err;
}

static void __exit ex3_exit(void)
{
	/* [X20: point 1]
	 * Explain following in here.
	 * This is the exit method, which is called in module_exit where 
	 * we can do the final operations before exiting the module. 
	 */
	return;
}

/* [X21: point 1]
 * Explain following in here.
 * The entry point of the module, where the module begins execution
 * when it is loaded into kernel using insmod with the input 
 * parametes. We are pointing this to the ex3_init method.
 */
module_init(ex3_init);

/* [X22: point 1]
 * Explain following in here.
 * This is the exit point of the module post all execution and we 
 * are pointing it to the function ex3_exit
 */
module_exit(ex3_exit);
