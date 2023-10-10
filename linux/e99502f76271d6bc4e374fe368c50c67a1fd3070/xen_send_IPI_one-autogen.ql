/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_send_IPI_one
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/xen-send-IPI-one
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-xen_send_IPI_one 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1547"
		and not target_0.getValue()="1554"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1548"
		and not target_1.getValue()="1555"
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
