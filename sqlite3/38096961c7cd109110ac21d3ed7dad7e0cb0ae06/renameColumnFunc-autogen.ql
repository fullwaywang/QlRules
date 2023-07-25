/**
 * @name sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-renameColumnFunc
 * @id cpp/sqlite3/38096961c7cd109110ac21d3ed7dad7e0cb0ae06/renameColumnFunc
 * @description sqlite3-38096961c7cd109110ac21d3ed7dad7e0cb0ae06-src/alter.c-renameColumnFunc CVE-2019-19645
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpSelect_1317, IfStmt target_4) {
	exists(AssignAndExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="selFlags"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpSelect_1317
		and target_0.getRValue().(ComplementExpr).getValue()="4292870143"
		and target_4.getCondition().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vsParse_1278, Variable vpSelect_1317, VariableAccess target_5, ExprStmt target_6, ExprStmt target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sqlite3SelectPrep")
		and target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsParse_1278
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpSelect_1317
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vsParse_1278, ExprStmt target_8, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="pSelect"
		and target_3.getQualifier().(ValueFieldAccess).getTarget().getName()="pNewTable"
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsParse_1278
		and target_3.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_4(Variable vsParse_1278, Variable vpSelect_1317, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vpSelect_1317
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rc"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsParse_1278
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sqlite3SelectPrep")
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsParse_1278
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="pSelect"
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_4.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_4.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(Literal).getValue()="0"
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="pTab"
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("RenameCtx")
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="pNewTable"
		and target_4.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsParse_1278
}

predicate func_5(Variable vpSelect_1317, VariableAccess target_5) {
		target_5.getTarget()=vpSelect_1317
}

predicate func_6(Variable vsParse_1278, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="rc"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsParse_1278
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_7(Variable vpSelect_1317, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("sqlite3WalkSelect")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("Walker")
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpSelect_1317
}

predicate func_8(Variable vsParse_1278, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("sqlite3 *")
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="7"
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ValueFieldAccess).getTarget().getName()="rc"
		and target_8.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vsParse_1278
}

from Function func, Variable vsParse_1278, Variable vpSelect_1317, PointerFieldAccess target_3, IfStmt target_4, VariableAccess target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vpSelect_1317, target_4)
and not func_1(vsParse_1278, vpSelect_1317, target_5, target_6, target_7)
and func_3(vsParse_1278, target_8, target_3)
and func_4(vsParse_1278, vpSelect_1317, target_4)
and func_5(vpSelect_1317, target_5)
and func_6(vsParse_1278, target_6)
and func_7(vpSelect_1317, target_7)
and func_8(vsParse_1278, target_8)
and vsParse_1278.getType().hasName("Parse")
and vpSelect_1317.getType().hasName("Select *")
and vsParse_1278.(LocalVariable).getFunction() = func
and vpSelect_1317.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
