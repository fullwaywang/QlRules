/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-create_new_objects
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/create-new-objects
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_upgrade/pg_upgrade.c-create_new_objects CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="\"%s/pg_restore\" %s --exit-on-error --verbose --dbname \"%s\" \"%s\""
		and not target_0.getValue()="\"%s/pg_restore\" %s --exit-on-error --verbose --dbname %s \"%s\""
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("initPQExpBuffer")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_2.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname="
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vold_db_307, ExprStmt target_11) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db_name"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_db_307
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("initPQExpBuffer")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("appendShellString")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_5.getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Variable vsql_file_name_305, Variable vlog_file_name_306, Variable vnew_cluster, AddressOfExpr target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("parallel_exec_prog")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_306
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="\"%s/pg_restore\" %s --exit-on-error --verbose --dbname %s \"%s\""
		and target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_cluster
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cluster_conn_opts")
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnew_cluster
		and target_7.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getTarget().getName()="data"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_7.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsql_file_name_305
		and target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation()))
}

/*predicate func_8(Function func) {
	exists(ValueFieldAccess target_8 |
		target_8.getTarget().getName()="data"
		and target_8.getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_8.getEnclosingFunction() = func)
}

*/
predicate func_9(Function func) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_9.getEnclosingFunction() = func)
}

predicate func_10(Variable vsql_file_name_305, Variable vlog_file_name_306, Variable vold_db_307, Variable vnew_cluster, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="db_name"
		and target_10.getQualifier().(VariableAccess).getTarget()=vold_db_307
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("parallel_exec_prog")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_306
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_cluster
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cluster_conn_opts")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnew_cluster
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsql_file_name_305
}

predicate func_11(Variable vlog_file_name_306, Variable vold_db_307, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_306
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_11.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pg_upgrade_dump_%u.log"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="db_oid"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_db_307
}

predicate func_14(Variable vnew_cluster, AddressOfExpr target_14) {
		target_14.getOperand().(VariableAccess).getTarget()=vnew_cluster
}

from Function func, Variable vsql_file_name_305, Variable vlog_file_name_306, Variable vold_db_307, Variable vnew_cluster, StringLiteral target_0, PointerFieldAccess target_10, ExprStmt target_11, AddressOfExpr target_14
where
func_0(func, target_0)
and not func_1(func)
and not func_2(func)
and not func_3(vold_db_307, target_11)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_7(vsql_file_name_305, vlog_file_name_306, vnew_cluster, target_14)
and not func_9(func)
and func_10(vsql_file_name_305, vlog_file_name_306, vold_db_307, vnew_cluster, target_10)
and func_11(vlog_file_name_306, vold_db_307, target_11)
and func_14(vnew_cluster, target_14)
and vsql_file_name_305.getType().hasName("char[1024]")
and vlog_file_name_306.getType().hasName("char[1024]")
and vold_db_307.getType().hasName("DbInfo *")
and vnew_cluster.getType().hasName("ClusterInfo")
and vsql_file_name_305.(LocalVariable).getFunction() = func
and vlog_file_name_306.(LocalVariable).getFunction() = func
and vold_db_307.(LocalVariable).getFunction() = func
and not vnew_cluster.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
