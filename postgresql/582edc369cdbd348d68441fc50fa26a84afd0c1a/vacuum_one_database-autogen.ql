/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-vacuum_one_database
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/vacuum-one-database
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/scripts/vacuumdb.c-vacuum_one_database CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Parameter vtables_335, Variable vdbtables_345, ExprStmt target_5, ExprStmt target_6) {
	exists(EqualityOperation target_2 |
		target_2.getAnOperand().(VariableAccess).getTarget()=vtables_335
		and target_2.getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdbtables_345
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("prepare_vacuum_command")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("PQExpBufferData")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("PGconn *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("vacuumingOptions *")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("const char *")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vtables_335, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("SimpleStringListCell *")
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vtables_335
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="head"
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtables_335
		and target_5.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="0"
}

predicate func_6(Parameter vtables_335, Variable vdbtables_345, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtables_335
		and target_6.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vdbtables_345
}

from Function func, Parameter vtables_335, Variable vdbtables_345, ExprStmt target_5, ExprStmt target_6
where
not func_2(vtables_335, vdbtables_345, target_5, target_6)
and func_5(vtables_335, target_5)
and func_6(vtables_335, vdbtables_345, target_6)
and vtables_335.getType().hasName("SimpleStringList *")
and vdbtables_345.getType().hasName("SimpleStringList")
and vtables_335.getFunction() = func
and vdbtables_345.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
