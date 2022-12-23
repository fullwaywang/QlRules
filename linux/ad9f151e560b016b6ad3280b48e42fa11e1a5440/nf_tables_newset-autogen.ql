/**
 * @name linux-ad9f151e560b016b6ad3280b48e42fa11e1a5440-nf_tables_newset
 * @id cpp/linux/ad9f151e560b016b6ad3280b48e42fa11e1a5440/nf_tables_newset
 * @description linux-ad9f151e560b016b6ad3280b48e42fa11e1a5440-nf_tables_newset 
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
