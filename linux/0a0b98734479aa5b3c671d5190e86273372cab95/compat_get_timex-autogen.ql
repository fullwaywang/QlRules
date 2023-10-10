/**
 * @name linux-0a0b98734479aa5b3c671d5190e86273372cab95-compat_get_timex
 * @id cpp/linux/0a0b98734479aa5b3c671d5190e86273372cab95/compat_get_timex
 * @description linux-0a0b98734479aa5b3c671d5190e86273372cab95-compat_get_timex 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vtxc_33, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtxc_33
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="208"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vtxc_33
where
not func_0(vtxc_33, func)
and vtxc_33.getType().hasName("timex *")
and vtxc_33.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
