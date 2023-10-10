/**
 * @name linux-eadb2f47a3ced5c64b23b90fd2a3463f63726066-kdb_local
 * @id cpp/linux/eadb2f47a3ced5c64b23b90fd2a3463f63726066/kdb_local
 * @description linux-eadb2f47a3ced5c64b23b90fd2a3463f63726066-kdb_local CVE-2022-21499
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kdb_check_for_lockdown")
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_0)
}

from Function func
where
not func_0(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
