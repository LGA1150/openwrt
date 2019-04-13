/* Shared library add-on to iptables to add POLIMI target support. 
Ex. Usage:
	iptables -t mangle -A INPUT -t POLIMI --findstring badstring --replacestring goodstring
*/

#include <string.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <xtables.h>



static struct xtables_target cmfw_target = {

	.name          = "CMFW",
	.version       = XTABLES_VERSION,
	.family        = NFPROTO_IPV4,
//	.size          = XT_ALIGN(sizeof(struct xt_cmfw_info)),
//	.userspacesize = XT_ALIGN(sizeof(struct xt_cmfw_info)),
//	.help          = cmfw_help,
//	.final_check   = cmfw_check,
//	.print         = cmfw_print,
//	.parse         = cmfw_parse,
//	.extra_opts    = cmfw_opts,

};

void _init(void)
{
	xtables_register_target(&cmfw_target);
}
