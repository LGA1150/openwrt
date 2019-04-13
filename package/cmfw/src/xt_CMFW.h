#ifndef _XT_POLIMI_TARGET_H
#define _XT_POLIMI_TARGET_H
#include <linux/types.h>
#define POLIMI_TARGET_MAX_STRING_SIZE 32

/*Parameters from user-space*/
struct xt_polimi_info {
	/*String to replace*/
	char			findString[POLIMI_TARGET_MAX_STRING_SIZE];
	/*Size of findString*/
	__u32			find_len;
	/*Replacing String*/
	char			replString[POLIMI_TARGET_MAX_STRING_SIZE];
	/*Size of replString*/
	__u32			repl_len;

};

#endif /* _XT_POLIMI_TARGET_H */

	
	
