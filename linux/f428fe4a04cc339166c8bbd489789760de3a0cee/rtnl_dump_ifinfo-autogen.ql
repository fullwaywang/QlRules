/**
 * @name linux-f428fe4a04cc339166c8bbd489789760de3a0cee-rtnl_dump_ifinfo
 * @id cpp/linux/f428fe4a04cc339166c8bbd489789760de3a0cee/rtnl-dump-ifinfo
 * @description linux-f428fe4a04cc339166c8bbd489789760de3a0cee-rtnl_dump_ifinfo 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

from Function func, Parameter vskb_1702
where
vskb_1702.getType().hasName("sk_buff *")
and vskb_1702.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
