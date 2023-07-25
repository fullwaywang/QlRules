/**
 * @name postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-ReconnectToServer
 * @id cpp/postgresql/582edc369cdbd348d68441fc50fa26a84afd0c1a/ReconnectToServer
 * @description postgresql-582edc369cdbd348d68441fc50fa26a84afd0c1a-src/bin/pg_dump/pg_backup_db.c-ReconnectToServer CVE-2018-1058
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vAH_82, ExprStmt target_1, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("ExecuteSqlQueryForSingleRow")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vAH_82
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false)"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vAH_82, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="connection"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vAH_82
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("PGconn *")
}

from Function func, Parameter vAH_82, ExprStmt target_1
where
not func_0(vAH_82, target_1, func)
and func_1(vAH_82, target_1)
and vAH_82.getType().hasName("ArchiveHandle *")
and vAH_82.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
