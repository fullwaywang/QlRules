/**
 * @name curl-8e65877870c1fac920b65219adec720df810aab9-ourWriteOut
 * @id cpp/curl/8e65877870c1fac920b65219adec720df810aab9/ourWriteOut
 * @description curl-8e65877870c1fac920b65219adec720df810aab9-src/tool_writeout.c-ourWriteOut CVE-2017-7407
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptr_110, BlockStmt target_2, ExprStmt target_3, EqualityOperation target_1) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_110
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vptr_110, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(CharLiteral).getValue()="92"
		and target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vptr_110
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vptr_110, BlockStmt target_2) {
		target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vptr_110
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(CharLiteral).getValue()="114"
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("fputc")
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(CharLiteral).getValue()="13"
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_2.getStmt(0).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(CharLiteral).getValue()="110"
}

predicate func_3(Variable vptr_110, ExprStmt target_3) {
		target_3.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vptr_110
		and target_3.getExpr().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

from Function func, Variable vptr_110, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vptr_110, target_2, target_3, target_1)
and func_1(vptr_110, target_2, target_1)
and func_2(vptr_110, target_2)
and func_3(vptr_110, target_3)
and vptr_110.getType().hasName("const char *")
and vptr_110.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
