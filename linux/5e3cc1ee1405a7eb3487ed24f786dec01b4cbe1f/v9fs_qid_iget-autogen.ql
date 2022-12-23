/**
 * @name linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_qid_iget
 * @id cpp/linux/5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f/v9fs_qid_iget
 * @description linux-5e3cc1ee1405a7eb3487ed24f786dec01b4cbe1f-v9fs_qid_iget 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
