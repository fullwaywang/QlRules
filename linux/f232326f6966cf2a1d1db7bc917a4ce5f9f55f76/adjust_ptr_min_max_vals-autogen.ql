/**
 * @name linux-f232326f6966cf2a1d1db7bc917a4ce5f9f55f76-adjust_ptr_min_max_vals
 * @id cpp/linux/f232326f6966cf2a1d1db7bc917a4ce5f9f55f76/adjust-ptr-min-max-vals
 * @description linux-f232326f6966cf2a1d1db7bc917a4ce5f9f55f76-adjust_ptr_min_max_vals 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="R%d tried to add from different maps or paths\n"
		and not target_0.getValue()="R%d tried to add from different maps, paths, or prohibited types\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(StringLiteral target_1 |
		target_1.getValue()="R%d tried to sub from different maps or paths\n"
		and not target_1.getValue()="R%d tried to sub from different maps, paths, or prohibited types\n"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
