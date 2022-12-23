/**
 * @name linux-072684e8c58d17e853f8e8b9f6d9ce2e58d2b036-f_hidg_write
 * @id cpp/linux/072684e8c58d17e853f8e8b9f6d9ce2e58d2b036/f_hidg_write
 * @description linux-072684e8c58d17e853f8e8b9f6d9ce2e58d2b036-f_hidg_write 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(LabelStmt target_0 |
		target_0.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func
where
func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
