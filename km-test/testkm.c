#include <linux/module.h>
#include <net/net_namespace.h>
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("HFQ - test kernel module");
MODULE_VERSION("1.0");
static int __init test_km_init(void) {
	printk("HFQ: test_km_init\n");
	printk("HFQ: sizeof(struct net) = %lu\n", sizeof(struct net));
	printk("HFQ: ilog2(sizeof(struct net)) = %d\n", ilog2(sizeof(struct net)));
	return 0;
}

static void __exit test_km_exit(void) {
	printk("HFQ: test_km_exit\n");
}

module_init(test_km_init);
module_exit(test_km_exit);
