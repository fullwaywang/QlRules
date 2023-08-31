/**
 * @name postgresql-11da97024abbe76b8c81e3f2375b2a62e9717c67-libpqrcv_connect
 * @id cpp/postgresql/11da97024abbe76b8c81e3f2375b2a62e9717c67/libpqrcv-connect
 * @description postgresql-11da97024abbe76b8c81e3f2375b2a62e9717c67-src/backend/replication/libpqwalreceiver/libpqwalreceiver.c-libpqrcv_connect CVE-2020-14349
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlogical_124, Variable vconn_127, IfStmt target_1, ExprStmt target_2, FunctionCall target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(VariableAccess).getTarget()=vlogical_124
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("libpqrcv_PQexec")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="streamConn"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_127
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(StringLiteral).getValue()="SELECT pg_catalog.set_config('search_path', '', false);"
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("PQresultStatus")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and target_0.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(DoStmt).getCondition() instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("PQclear")
		and target_0.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("PGresult *")
		and (func.getEntryPoint().(BlockStmt).getStmt(22)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(22).getFollowingStmt()=target_0)
		and target_1.getCondition().(VariableAccess).getLocation().isBefore(target_0.getCondition().(VariableAccess).getLocation())
		and target_0.getCondition().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlogical_124, IfStmt target_1) {
		target_1.getCondition().(VariableAccess).getTarget()=vlogical_124
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char *[5]")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(PrefixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="client_encoding"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char *[5]")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("GetDatabaseEncodingName")
}

predicate func_2(Parameter vlogical_124, Variable vconn_127, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="logical"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_127
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vlogical_124
}

predicate func_3(Variable vconn_127, FunctionCall target_3) {
		target_3.getTarget().hasName("PQerrorMessage")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="streamConn"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_127
}

from Function func, Parameter vlogical_124, Variable vconn_127, IfStmt target_1, ExprStmt target_2, FunctionCall target_3
where
not func_0(vlogical_124, vconn_127, target_1, target_2, target_3, func)
and func_1(vlogical_124, target_1)
and func_2(vlogical_124, vconn_127, target_2)
and func_3(vconn_127, target_3)
and vlogical_124.getType().hasName("bool")
and vconn_127.getType().hasName("WalReceiverConn *")
and vlogical_124.getFunction() = func
and vconn_127.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
