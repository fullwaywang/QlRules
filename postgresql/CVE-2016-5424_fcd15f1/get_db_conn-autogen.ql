/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-get_db_conn
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/get-db-conn
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_upgrade/server.c-get_db_conn CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vos_info, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(VariableAccess).getTarget()=vos_info
}

predicate func_2(Variable vconn_opts_54) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("initPQExpBuffer")
		and target_2.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54)
}

predicate func_3(Variable vconn_opts_54) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("appendPQExpBufferStr")
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_3.getArgument(1).(StringLiteral).getValue()="dbname=")
}

predicate func_4(Parameter vdb_name_52, Variable vconn_opts_54, FunctionCall target_25, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdb_name_52
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_4)
		and target_25.getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vconn_opts_54, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_5.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" user="
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_5))
}

predicate func_6(Variable vconn_opts_54, Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_6.getExpr().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_6 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_6))
}

predicate func_7(Parameter vcluster_52, Variable vconn_opts_54, Function func) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBuffer")
		and target_7.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_7.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" port=%d"
		and target_7.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="port"
		and target_7.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_7))
}

predicate func_8(Variable vconn_opts_54, PointerFieldAccess target_28) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_8.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_8.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()=" host="
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_8
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28)
}

predicate func_9(Parameter vcluster_52, Variable vconn_opts_54, PointerFieldAccess target_28, IfStmt target_30) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(FunctionCall).getTarget().hasName("appendConnStrVal")
		and target_9.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="sockdir"
		and target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
		and target_30.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_10(Variable vconn_opts_54, FunctionCall target_25, Function func) {
	exists(ExprStmt target_10 |
		target_10.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("PGconn *")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("PQconnectdb")
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opts_54
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_10 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_10)
		and target_10.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_25.getArgument(0).(VariableAccess).getLocation()))
}

predicate func_12(Variable vconn_opts_54, Function func) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_12.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vconn_opts_54
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_12 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_12))
}

predicate func_14(Variable vos_info, ValueFieldAccess target_14) {
		target_14.getTarget().getName()="user"
		and target_14.getQualifier().(VariableAccess).getTarget()=vos_info
}

predicate func_15(Parameter vcluster_52, PointerFieldAccess target_15) {
		target_15.getTarget().getName()="sockdir"
		and target_15.getQualifier().(VariableAccess).getTarget()=vcluster_52
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_16(Parameter vcluster_52, PointerFieldAccess target_16) {
		target_16.getTarget().getName()="port"
		and target_16.getQualifier().(VariableAccess).getTarget()=vcluster_52
		and target_16.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_17(Parameter vdb_name_52, VariableAccess target_17) {
		target_17.getTarget()=vdb_name_52
		and target_17.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_18(Parameter vcluster_52, Parameter vdb_name_52, Variable vconn_opts_54, FunctionCall target_18) {
		target_18.getTarget().hasName("snprintf")
		and target_18.getArgument(0).(VariableAccess).getTarget()=vconn_opts_54
		and target_18.getArgument(1).(SizeofExprOperator).getValue()="1252"
		and target_18.getArgument(2).(StringLiteral).getValue()="dbname = '%s' user = '%s' host = '%s' port = %d"
		and target_18.getArgument(3).(VariableAccess).getTarget()=vdb_name_52
		and target_18.getArgument(4) instanceof ValueFieldAccess
		and target_18.getArgument(5).(PointerFieldAccess).getTarget().getName()="sockdir"
		and target_18.getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
		and target_18.getArgument(6).(PointerFieldAccess).getTarget().getName()="port"
		and target_18.getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
}

predicate func_19(Parameter vcluster_52, Parameter vdb_name_52, Variable vconn_opts_54, FunctionCall target_19) {
		target_19.getTarget().hasName("snprintf")
		and target_19.getArgument(0).(VariableAccess).getTarget()=vconn_opts_54
		and target_19.getArgument(1).(SizeofExprOperator).getValue()="1252"
		and target_19.getArgument(2).(StringLiteral).getValue()="dbname = '%s' user = '%s' port = %d"
		and target_19.getArgument(3).(VariableAccess).getTarget()=vdb_name_52
		and target_19.getArgument(4) instanceof ValueFieldAccess
		and target_19.getArgument(5).(PointerFieldAccess).getTarget().getName()="port"
		and target_19.getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
}

predicate func_20(Variable vconn_opts_54, VariableAccess target_20) {
		target_20.getTarget()=vconn_opts_54
		and target_20.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("PQconnectdb")
}

predicate func_25(Variable vconn_opts_54, FunctionCall target_25) {
		target_25.getTarget().hasName("PQconnectdb")
		and target_25.getArgument(0).(VariableAccess).getTarget()=vconn_opts_54
}

predicate func_28(Parameter vcluster_52, PointerFieldAccess target_28) {
		target_28.getTarget().getName()="sockdir"
		and target_28.getQualifier().(VariableAccess).getTarget()=vcluster_52
}

predicate func_30(Parameter vcluster_52, IfStmt target_30) {
		target_30.getCondition().(PointerFieldAccess).getTarget().getName()="sockdir"
		and target_30.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcluster_52
		and target_30.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_30.getElse().(ExprStmt).getExpr() instanceof FunctionCall
}

from Function func, Parameter vcluster_52, Parameter vdb_name_52, Variable vconn_opts_54, Variable vos_info, ValueFieldAccess target_1, ValueFieldAccess target_14, PointerFieldAccess target_15, PointerFieldAccess target_16, VariableAccess target_17, FunctionCall target_18, FunctionCall target_19, VariableAccess target_20, FunctionCall target_25, PointerFieldAccess target_28, IfStmt target_30
where
func_1(vos_info, target_1)
and not func_2(vconn_opts_54)
and not func_3(vconn_opts_54)
and not func_4(vdb_name_52, vconn_opts_54, target_25, func)
and not func_5(vconn_opts_54, func)
and not func_6(vconn_opts_54, func)
and not func_7(vcluster_52, vconn_opts_54, func)
and not func_8(vconn_opts_54, target_28)
and not func_9(vcluster_52, vconn_opts_54, target_28, target_30)
and not func_10(vconn_opts_54, target_25, func)
and not func_12(vconn_opts_54, func)
and func_14(vos_info, target_14)
and func_15(vcluster_52, target_15)
and func_16(vcluster_52, target_16)
and func_17(vdb_name_52, target_17)
and func_18(vcluster_52, vdb_name_52, vconn_opts_54, target_18)
and func_19(vcluster_52, vdb_name_52, vconn_opts_54, target_19)
and func_20(vconn_opts_54, target_20)
and func_25(vconn_opts_54, target_25)
and func_28(vcluster_52, target_28)
and func_30(vcluster_52, target_30)
and vcluster_52.getType().hasName("ClusterInfo *")
and vdb_name_52.getType().hasName("const char *")
and vconn_opts_54.getType().hasName("char[1252]")
and vos_info.getType().hasName("OSInfo")
and vcluster_52.getFunction() = func
and vdb_name_52.getFunction() = func
and vconn_opts_54.(LocalVariable).getFunction() = func
and not vos_info.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
