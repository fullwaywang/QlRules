/**
 * @name linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-unqueue_me_pi
 * @id cpp/linux/c64396cc36c6e60704ab06c1fb1c4a46179c9120/unqueue-me-pi
 * @description linux-c64396cc36c6e60704ab06c1fb1c4a46179c9120-unqueue_me_pi 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1216"
		and not target_0.getValue()="1219"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1217"
		and not target_1.getValue()="1220"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
