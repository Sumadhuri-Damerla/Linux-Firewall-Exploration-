#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>

static struct nf_hook_ops filterHook_IN;

static struct nf_hook_ops filterHook_OUT;

struct iphdr *iph;
struct tcphdr *tcph;

//egress
unsigned int out_filter(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {
  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  // Prevent machine A to telnet to machine B
  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->daddr == in_aton("10.0.2.6")) {
    printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
	((unsigned char *)&iph->daddr)[0],
	((unsigned char *)&iph->daddr)[1],
	((unsigned char *)&iph->daddr)[2],
	((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  }
  //prevent machine A to telnet to pfw.edu
  else if(tcph->dest == htons(80) && iph->daddr == in_aton("52.205.6.225")){
     printk(KERN_INFO "Dropping telnet packet to %d.%d.%d.%d\n",
	((unsigned char *)&iph->daddr)[0],
	((unsigned char *)&iph->daddr)[1],
	((unsigned char *)&iph->daddr)[2],
	((unsigned char *)&iph->daddr)[3]);
     return NF_DROP;
  }
  //prevent machine A from ssh to machine B
   else if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22) && iph->daddr == in_aton("10.0.2.6")) {
    printk(KERN_INFO "Dropping ssh packet to %d.%d.%d.%d\n",
	((unsigned char *)&iph->daddr)[0],
	((unsigned char *)&iph->daddr)[1],
	((unsigned char *)&iph->daddr)[2],
	((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  }
  else{
    return NF_ACCEPT;
  }
}

//ingress
unsigned int in_filter(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) {

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

 //Prevent machine B to telnet to machine A
  if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23) && iph->saddr == in_aton("10.0.2.6")){
     printk(KERN_INFO "Dropping telnet packet from %d.%d.%d.%d\n",
	((unsigned char *)&iph->saddr)[0],
	((unsigned char *)&iph->saddr)[1],
	((unsigned char *)&iph->saddr)[2],
	((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;
  } 
  //Prevent machine B to ssh to machine A
  else if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(22) && iph->saddr == in_aton("10.0.2.6")){
     printk(KERN_INFO "Dropping ssh packet from %d.%d.%d.%d\n",
	((unsigned char *)&iph->saddr)[0],
	((unsigned char *)&iph->saddr)[1],
	((unsigned char *)&iph->saddr)[2],
	((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;
  } 
  else {
    return NF_ACCEPT;
  }
}

int setUpFilter(void) {
        //ingress
	printk(KERN_INFO "Registering a in-filter.\n");
	filterHook_IN.hook = in_filter;

	filterHook_IN.hooknum = NF_INET_PRE_ROUTING; 
	filterHook_IN.pf = PF_INET;
	filterHook_IN.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_hook(&filterHook_IN);


        //egress 
	printk(KERN_INFO "Registering a out-filter.\n");
        filterHook_OUT.hook = out_filter;
        filterHook_OUT.hooknum = NF_INET_POST_ROUTING;
        filterHook_OUT.pf = PF_INET;
        filterHook_OUT.priority = NF_IP_PRI_FIRST;
        nf_register_hook(&filterHook_OUT);      
        return 0;
}

void removeFilter(void) {
	printk(KERN_INFO "task2 firewall is being removed.\n");
	nf_unregister_hook(&filterHook_IN);
	nf_unregister_hook(&filterHook_OUT);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");
