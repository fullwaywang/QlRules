/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-generate_old_dump
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/generate-old-dump
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_upgrade/dump.c-generate_old_dump CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="\"%s/pg_dump\" %s --schema-only --quote-all-identifiers --binary-upgrade --format=custom %s --file=\"%s\" \"%s\""
		and not target_0.getValue()="\"%s/pg_dump\" %s --schema-only --quote-all-identifiers --binary-upgrade --format=custom %s --file=\"%s\" %s"
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

predicate func_3(Variable vold_db_48, ExprStmt target_11) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="db_name"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_db_48
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

predicate func_7(Variable vnew_cluster, Variable vold_cluster, Variable vlog_opts, Variable vsql_file_name_46, Variable vlog_file_name_47, ValueFieldAccess target_12, ValueFieldAccess target_13, ConditionalExpr target_14) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("parallel_exec_prog")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_47
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="\"%s/pg_dump\" %s --schema-only --quote-all-identifiers --binary-upgrade --format=custom %s --file=\"%s\" %s"
		and target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_cluster
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cluster_conn_opts")
		and target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vold_cluster
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="verbose"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlog_opts
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="--verbose"
		and target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_7.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsql_file_name_46
		and target_7.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getTarget().getName()="data"
		and target_7.getExpr().(FunctionCall).getArgument(7).(ValueFieldAccess).getQualifier().(VariableAccess).getType().hasName("PQExpBufferData")
		and target_12.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_13.getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_14.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
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

predicate func_10(Variable vnew_cluster, Variable vold_cluster, Variable vlog_opts, Variable vsql_file_name_46, Variable vlog_file_name_47, Variable vold_db_48, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="db_name"
		and target_10.getQualifier().(VariableAccess).getTarget()=vold_db_48
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("parallel_exec_prog")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_47
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getTarget().getName()="bindir"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnew_cluster
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("cluster_conn_opts")
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vold_cluster
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(ValueFieldAccess).getTarget().getName()="verbose"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlog_opts
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="--verbose"
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vsql_file_name_46
}

predicate func_11(Variable vlog_file_name_47, Variable vold_db_48, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlog_file_name_47
		and target_11.getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_11.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="pg_upgrade_dump_%u.log"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="db_oid"
		and target_11.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vold_db_48
}

predicate func_12(Variable vnew_cluster, ValueFieldAccess target_12) {
		target_12.getTarget().getName()="bindir"
		and target_12.getQualifier().(VariableAccess).getTarget()=vnew_cluster
}

predicate func_13(Variable vold_cluster, ValueFieldAccess target_13) {
		target_13.getTarget().getName()="dbarr"
		and target_13.getQualifier().(VariableAccess).getTarget()=vold_cluster
}

predicate func_14(Variable vlog_opts, ConditionalExpr target_14) {
		target_14.getCondition().(ValueFieldAccess).getTarget().getName()="verbose"
		and target_14.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vlog_opts
		and target_14.getThen().(StringLiteral).getValue()="--verbose"
		and target_14.getElse().(StringLiteral).getValue()=""
}

from Function func, Variable vnew_cluster, Variable vold_cluster, Variable vlog_opts, Variable vsql_file_name_46, Variable vlog_file_name_47, Variable vold_db_48, StringLiteral target_0, PointerFieldAccess target_10, ExprStmt target_11, ValueFieldAccess target_12, ValueFieldAccess target_13, ConditionalExpr target_14
where
func_0(func, target_0)
and not func_1(func)
and not func_2(func)
and not func_3(vold_db_48, target_11)
and not func_4(func)
and not func_5(func)
and not func_6(func)
and not func_7(vnew_cluster, vold_cluster, vlog_opts, vsql_file_name_46, vlog_file_name_47, target_12, target_13, target_14)
and not func_9(func)
and func_10(vnew_cluster, vold_cluster, vlog_opts, vsql_file_name_46, vlog_file_name_47, vold_db_48, target_10)
and func_11(vlog_file_name_47, vold_db_48, target_11)
and func_12(vnew_cluster, target_12)
and func_13(vold_cluster, target_13)
and func_14(vlog_opts, target_14)
and vnew_cluster.getType().hasName("ClusterInfo")
and vold_cluster.getType().hasName("ClusterInfo")
and vlog_opts.getType().hasName("LogOpts")
and vsql_file_name_46.getType().hasName("char[1024]")
and vlog_file_name_47.getType().hasName("char[1024]")
and vold_db_48.getType().hasName("DbInfo *")
and not vnew_cluster.getParentScope+() = func
and not vold_cluster.getParentScope+() = func
and not vlog_opts.getParentScope+() = func
and vsql_file_name_46.(LocalVariable).getFunction() = func
and vlog_file_name_47.(LocalVariable).getFunction() = func
and vold_db_48.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
