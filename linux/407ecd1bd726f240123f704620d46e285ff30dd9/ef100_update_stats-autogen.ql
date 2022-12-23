/**
 * @name linux-407ecd1bd726f240123f704620d46e285ff30dd9-ef100_update_stats
 * @id cpp/linux/407ecd1bd726f240123f704620d46e285ff30dd9/ef100_update_stats
 * @description linux-407ecd1bd726f240123f704620d46e285ff30dd9-ef100_update_stats 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vmc_stats_604, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vmc_stats_604
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

from Function func, Variable vmc_stats_604
where
not func_0(vmc_stats_604, func)
and vmc_stats_604.getType().hasName("__le64 *")
and vmc_stats_604.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
