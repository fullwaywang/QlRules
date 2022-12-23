/**
 * @name linux-1e38da300e1e395a15048b0af1e5305bd91402f6-timerfd_remove_cancel
 * @id cpp/linux/1e38da300e1e395a15048b0af1e5305bd91402f6/timerfd-remove-cancel
 * @description linux-1e38da300e1e395a15048b0af1e5305bd91402f6-timerfd_remove_cancel 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("list_del_rcu")
		and not target_0.getTarget().hasName("__timerfd_remove_cancel")
		and target_0.getArgument(0).(AddressOfExpr).getOperand() instanceof PointerFieldAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vctx_115) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cancel_lock"
		and target_1.getQualifier().(VariableAccess).getTarget()=vctx_115)
}

predicate func_6(Parameter vctx_115, Variable vcancel_lock, Function func) {
	exists(IfStmt target_6 |
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="might_cancel"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_115
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="might_cancel"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_115
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_6.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcancel_lock
		and target_6.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr() instanceof FunctionCall
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_6.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcancel_lock
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6)
}

predicate func_9(Parameter vctx_115) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="clist"
		and target_9.getQualifier().(VariableAccess).getTarget()=vctx_115)
}

from Function func, Parameter vctx_115, Variable vcancel_lock
where
func_0(func)
and not func_1(vctx_115)
and func_6(vctx_115, vcancel_lock, func)
and func_9(vctx_115)
and vctx_115.getType().hasName("timerfd_ctx *")
and vctx_115.getParentScope+() = func
and not vcancel_lock.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
