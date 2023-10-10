/**
 * @name linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-__local_bh_enable
 * @id cpp/linux/81f9c4e4177d31ced6f52a89bb70e93bfb77ca03/--local-bh-enable
 * @description linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-__local_bh_enable 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcnt_138, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("preempt_count")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vcnt_138
		and target_0.getThen().(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(DoStmt).getStmt().(BlockStmt).toString() = "{ ... }"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vcnt_138
where
not func_0(vcnt_138, func)
and vcnt_138.getType().hasName("unsigned int")
and vcnt_138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
