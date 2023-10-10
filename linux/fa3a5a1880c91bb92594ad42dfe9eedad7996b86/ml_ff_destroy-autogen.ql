/**
 * @name linux-fa3a5a1880c91bb92594ad42dfe9eedad7996b86-ml_ff_destroy
 * @id cpp/linux/fa3a5a1880c91bb92594ad42dfe9eedad7996b86/ml_ff_destroy
 * @description linux-fa3a5a1880c91bb92594ad42dfe9eedad7996b86-ml_ff_destroy 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vml_490, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("del_timer_sync")
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="timer"
		and target_0.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vml_490
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Variable vml_490
where
not func_0(vml_490, func)
and vml_490.getType().hasName("ml_device *")
and vml_490.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
