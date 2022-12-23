/**
 * @name linux-93e2be344a7db169b7119de21ac1bf253b8c6907-intr_callback
 * @id cpp/linux/93e2be344a7db169b7119de21ac1bf253b8c6907/intr_callback
 * @description linux-93e2be344a7db169b7119de21ac1bf253b8c6907-intr_callback 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("net_ratelimit")
		and target_0.getThen() instanceof DoStmt
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vtp_1849) {
	exists(DoStmt target_1 |
		target_1.getCondition().(Literal).getValue()="0"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="msg_enable"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtp_1849
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("netdev_info")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="netdev"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtp_1849
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="intr status -EOVERFLOW\n")
}

from Function func, Variable vtp_1849
where
not func_0(func)
and func_1(vtp_1849)
and vtp_1849.getType().hasName("r8152 *")
and vtp_1849.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
