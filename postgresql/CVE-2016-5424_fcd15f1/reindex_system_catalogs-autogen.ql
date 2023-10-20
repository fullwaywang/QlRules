/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-reindex_system_catalogs
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/reindex-system-catalogs
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/scripts/reindexdb.c-reindex_system_catalogs CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("fmtId")
		and target_0.getArgument(0) instanceof FunctionCall
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("PQExpBufferData")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" SYSTEM %s;"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vconn_363, FunctionCall target_1) {
		target_1.getTarget().hasName("PQdb")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vconn_363
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("PQExpBufferData")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" SYSTEM %s;"
}

from Function func, Variable vconn_363, FunctionCall target_1
where
not func_0(func)
and func_1(vconn_363, target_1)
and vconn_363.getType().hasName("PGconn *")
and vconn_363.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
