/**
 * @name linux-1e38da300e1e395a15048b0af1e5305bd91402f6-timerfd_setup_cancel
 * @id cpp/linux/1e38da300e1e395a15048b0af1e5305bd91402f6/timerfd-setup-cancel
 * @description linux-1e38da300e1e395a15048b0af1e5305bd91402f6-timerfd_setup_cancel NULL
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctx_133) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("timerfd_remove_cancel")
		and not target_0.getTarget().hasName("__timerfd_remove_cancel")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctx_133)
}

predicate func_1(Parameter vctx_133, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("spin_lock")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cancel_lock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_133
		and (func.getEntryPoint().(BlockStmt).getStmt(0)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(0).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vctx_133, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="cancel_lock"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_133
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_2))
}

predicate func_4(Parameter vctx_133, Parameter vflags_133) {
	exists(IfStmt target_4 |
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="might_cancel"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_133
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof FunctionCall
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="clockid"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_133
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="clockid"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_133
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="8"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_133
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_133
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vctx_133, Parameter vflags_133
where
func_0(vctx_133)
and not func_1(vctx_133, func)
and not func_2(vctx_133, func)
and func_4(vctx_133, vflags_133)
and vctx_133.getType().hasName("timerfd_ctx *")
and vflags_133.getType().hasName("int")
and vctx_133.getParentScope+() = func
and vflags_133.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
