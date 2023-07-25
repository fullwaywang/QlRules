/**
 * @name sqlite3-1e9c47be1e81e94a67f788c98fd70e8bf70e3746-corruptSchema
 * @id cpp/sqlite3/1e9c47be1e81e94a67f788c98fd70e8bf70e3746/corruptSchema
 * @description sqlite3-1e9c47be1e81e94a67f788c98fd70e8bf70e3746-src/prepare.c-corruptSchema CVE-2018-8740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vzExtra_25, ExprStmt target_2, IfStmt target_3) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(VariableAccess).getTarget()=vzExtra_25
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vzExtra_25
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_0.getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vzExtra_25, ExprStmt target_2, VariableAccess target_1) {
		target_1.getTarget()=vzExtra_25
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Parameter vzExtra_25, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3MPrintf")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("sqlite3 *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%z - %s"
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("char *")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vzExtra_25
}

predicate func_3(Parameter vzExtra_25, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vzExtra_25
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sqlite3MPrintf")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("sqlite3 *")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%z - %s"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType().hasName("char *")
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vzExtra_25
}

from Function func, Parameter vzExtra_25, VariableAccess target_1, ExprStmt target_2, IfStmt target_3
where
not func_0(vzExtra_25, target_2, target_3)
and func_1(vzExtra_25, target_2, target_1)
and func_2(vzExtra_25, target_2)
and func_3(vzExtra_25, target_3)
and vzExtra_25.getType().hasName("const char *")
and vzExtra_25.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
