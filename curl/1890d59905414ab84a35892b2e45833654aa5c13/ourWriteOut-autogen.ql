/**
 * @name curl-1890d59905414ab84a35892b2e45833654aa5c13-ourWriteOut
 * @id cpp/curl/1890d59905414ab84a35892b2e45833654aa5c13/ourWriteOut
 * @description curl-1890d59905414ab84a35892b2e45833654aa5c13-src/tool_writeout.c-ourWriteOut CVE-2017-7407
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptr_110, BlockStmt target_2, LogicalAndExpr target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_110
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vptr_110, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(CharLiteral).getValue()="37"
		and target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_110
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vptr_110, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="37"
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_110
		and target_2.getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fputc")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(CharLiteral).getValue()="37"
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_110
		and target_2.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="123"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_110
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fputc")
		and target_2.getStmt(0).(IfStmt).getElse().(BlockStmt).getStmt(3).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fputc")
}

predicate func_3(Variable vptr_110, LogicalAndExpr target_3) {
		target_3.getAnOperand().(VariableAccess).getTarget()=vptr_110
		and target_3.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_110
}

from Function func, Variable vptr_110, EqualityOperation target_1, BlockStmt target_2, LogicalAndExpr target_3
where
not func_0(vptr_110, target_2, target_3, target_1)
and func_1(vptr_110, target_2, target_1)
and func_2(vptr_110, target_2)
and func_3(vptr_110, target_3)
and vptr_110.getType().hasName("const char *")
and vptr_110.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
