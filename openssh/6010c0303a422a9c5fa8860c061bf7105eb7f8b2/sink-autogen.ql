/**
 * @name openssh-6010c0303a422a9c5fa8860c061bf7105eb7f8b2-sink
 * @id cpp/openssh/6010c0303a422a9c5fa8860c061bf7105eb7f8b2/sink
 * @description openssh-6010c0303a422a9c5fa8860c061bf7105eb7f8b2-scp.c-sink CVE-2018-20685
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcp_985, BlockStmt target_2, LogicalOrExpr target_3, LogicalOrExpr target_4) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcp_985
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcp_985
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="."
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcp_985
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=".."
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vcp_985, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcp_985
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="47"
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcp_985
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=".."
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vcp_985, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("run_err")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="error: unexpected filename: %s"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcp_985
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("exit")
		and target_2.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="1"
}

predicate func_3(Variable vcp_985, LogicalOrExpr target_3) {
		target_3.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vcp_985
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vcp_985
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="32"
}

predicate func_4(Variable vcp_985, LogicalOrExpr target_4) {
		target_4.getAnOperand() instanceof EqualityOperation
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcp_985
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=".."
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vcp_985, EqualityOperation target_1, BlockStmt target_2, LogicalOrExpr target_3, LogicalOrExpr target_4
where
not func_0(vcp_985, target_2, target_3, target_4)
and func_1(vcp_985, target_2, target_1)
and func_2(vcp_985, target_2)
and func_3(vcp_985, target_3)
and func_4(vcp_985, target_4)
and vcp_985.getType().hasName("char *")
and vcp_985.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
