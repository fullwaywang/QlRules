/**
 * @name linux-0c9acb1af77a3cb8707e43f45b72c95266903cee-vcs_write
 * @id cpp/linux/0c9acb1af77a3cb8707e43f45b72c95266903cee/vcs_write
 * @description linux-0c9acb1af77a3cb8707e43f45b72c95266903cee-vcs_write 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vinode_449, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("iminor")
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vinode_449
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-95"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="95"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

from Function func, Variable vinode_449
where
not func_0(vinode_449, func)
and vinode_449.getType().hasName("inode *")
and vinode_449.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
