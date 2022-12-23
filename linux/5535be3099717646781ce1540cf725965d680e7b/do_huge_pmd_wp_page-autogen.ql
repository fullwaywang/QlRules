/**
 * @name linux-5535be3099717646781ce1540cf725965d680e7b-do_huge_pmd_wp_page
 * @id cpp/linux/5535be3099717646781ce1540cf725965d680e7b/do_huge_pmd_wp_page
 * @description linux-5535be3099717646781ce1540cf725965d680e7b-do_huge_pmd_wp_page CVE-2016-5195
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="1001"
		and not target_0.getValue()="997"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="1002"
		and not target_1.getValue()="998"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1003"
		and not target_2.getValue()="999"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="1004"
		and not target_3.getValue()="1000"
		and target_3.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
