/**
 * @name linux-b29c457a6511435960115c0f548c4360d5f4801d-translate_compat_table
 * @id cpp/linux/b29c457a6511435960115c0f548c4360d5f4801d/translate-compat-table
 * @description linux-b29c457a6511435960115c0f548c4360d5f4801d-translate_compat_table 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnewinfo_1160, Variable vsize_1164, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="entries"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewinfo_1160
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_1164
		and (func.getEntryPoint().(BlockStmt).getStmt(21)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(21).getFollowingStmt()=target_0))
}

predicate func_1(Variable vnewinfo_1160) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vnewinfo_1160
		and target_1.getParent().(IfStmt).getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_2(Variable vsize_1164) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("xt_alloc_table_info")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vsize_1164)
}

from Function func, Variable vnewinfo_1160, Variable vsize_1164
where
not func_0(vnewinfo_1160, vsize_1164, func)
and vnewinfo_1160.getType().hasName("xt_table_info *")
and func_1(vnewinfo_1160)
and vsize_1164.getType().hasName("unsigned int")
and func_2(vsize_1164)
and vnewinfo_1160.getParentScope+() = func
and vsize_1164.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
