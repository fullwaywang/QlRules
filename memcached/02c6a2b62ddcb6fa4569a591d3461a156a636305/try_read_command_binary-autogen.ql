/**
 * @name memcached-02c6a2b62ddcb6fa4569a591d3461a156a636305-try_read_command_binary
 * @id cpp/memcached/02c6a2b62ddcb6fa4569a591d3461a156a636305-try-read-command-binary
 * @description memcached-02c6a2b62ddcb6fa4569a591d3461a156a636305-try_read_command_binary CVE-2020-10931
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vextlen_6154, ExprStmt target_3) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vextlen_6154
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="20"
		and target_1.getThen().(Literal).getValue()="20"
		and target_1.getElse().(VariableAccess).getTarget()=vextlen_6154
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char[44]")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rcurr"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("conn *")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vextlen_6154
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Variable vextlen_6154, VariableAccess target_2) {
		target_2.getTarget()=vextlen_6154
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char[44]")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rcurr"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("conn *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
}

predicate func_3(Variable vextlen_6154, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget().getType().hasName("char[44]")
		and target_3.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rcurr"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("conn *")
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(SizeofExprOperator).getValue()="24"
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vextlen_6154
}

from Function func, Variable vextlen_6154, VariableAccess target_2, ExprStmt target_3
where
not func_1(vextlen_6154, target_3)
and func_2(vextlen_6154, target_2)
and func_3(vextlen_6154, target_3)
and vextlen_6154.getType().hasName("uint8_t")
and vextlen_6154.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
