/**
 * @name linux-350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef-check_btf_info
 * @id cpp/linux/350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef/check_btf_info
 * @description linux-350a5c4dd2452ea999cc5e1d4a8dbf12de2f97ef-check_btf_info 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vbtf_9047, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("btf_is_kernel")
		and target_0.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtf_9047
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("btf_put")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbtf_9047
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-13"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="13"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_3(Variable vbtf_9047) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("PTR_ERR")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vbtf_9047)
}

from Function func, Variable vbtf_9047
where
not func_0(vbtf_9047, func)
and vbtf_9047.getType().hasName("btf *")
and func_3(vbtf_9047)
and vbtf_9047.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
