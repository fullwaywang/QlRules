/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-libpqConnect
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/libpqConnect
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/pg_rewind/libpq_fetch.c-libpqConnect CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vres_48, Variable vconn, FunctionCall target_4, ExprStmt target_5, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_48
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQexec")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false)"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vres_48, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("PQresultStatus")
		and target_1.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vres_48
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("pg_fatal")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="could not clear search_path: %s"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("PQresultErrorMessage")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vres_48
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_1))
}

predicate func_4(Variable vconn, FunctionCall target_4) {
		target_4.getTarget().hasName("PQerrorMessage")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vconn
}

predicate func_5(Variable vres_48, Variable vconn, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vres_48
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQexec")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SET synchronous_commit = off"
}

from Function func, Variable vres_48, Variable vconn, FunctionCall target_4, ExprStmt target_5
where
not func_0(vres_48, vconn, target_4, target_5, func)
and not func_1(vres_48, func)
and func_4(vconn, target_4)
and func_5(vres_48, vconn, target_5)
and vres_48.getType().hasName("PGresult *")
and vconn.getType().hasName("PGconn *")
and vres_48.(LocalVariable).getFunction() = func
and not vconn.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
