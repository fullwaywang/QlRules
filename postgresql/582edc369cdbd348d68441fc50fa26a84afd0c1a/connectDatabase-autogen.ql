/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-connectDatabase
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/connectDatabase
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/pg_dump/pg_dumpall.c-connectDatabase CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_1525, FunctionCall target_0) {
		target_0.getTarget().hasName("executeCommand")
		and not target_0.getTarget().hasName("PQclear")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vconn_1525
		and target_0.getArgument(1).(StringLiteral).getValue()="SET search_path = pg_catalog"
}

predicate func_1(Variable vconn_1525, ExprStmt target_3, ReturnStmt target_4) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("executeQuery")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vconn_1525
		and target_1.getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false)"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation())
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(VariableAccess).getLocation()))
}

predicate func_2(Variable vconn_1525, VariableAccess target_2) {
		target_2.getTarget()=vconn_1525
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_3(Variable vconn_1525, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQserverVersion")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_1525
}

predicate func_4(Variable vconn_1525, ReturnStmt target_4) {
		target_4.getExpr().(VariableAccess).getTarget()=vconn_1525
}

from Function func, Variable vconn_1525, FunctionCall target_0, VariableAccess target_2, ExprStmt target_3, ReturnStmt target_4
where
func_0(vconn_1525, target_0)
and not func_1(vconn_1525, target_3, target_4)
and func_2(vconn_1525, target_2)
and func_3(vconn_1525, target_3)
and func_4(vconn_1525, target_4)
and vconn_1525.getType().hasName("PGconn *")
and vconn_1525.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
