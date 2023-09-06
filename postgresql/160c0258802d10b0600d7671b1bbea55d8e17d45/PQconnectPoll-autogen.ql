/**
 * @name postgresql-160c0258802d10b0600d7671b1bbea55d8e17d45-PQconnectPoll
 * @id cpp/postgresql/160c0258802d10b0600d7671b1bbea55d8e17d45/PQconnectPoll
 * @description postgresql-160c0258802d10b0600d7671b1bbea55d8e17d45-src/interfaces/libpq/fe-connect.c-PQconnectPoll CVE-2021-23222
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_2246, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="inCursor"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2246
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="inEnd"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2246
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2246
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="received unencrypted data after SSL response\n"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(ExprStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()
}

predicate func_2(Parameter vconn_2246, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("PostgresPollingStatusType")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pqsecure_open_client")
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vconn_2246
}

predicate func_3(Parameter vconn_2246, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_2246
}

from Function func, Parameter vconn_2246, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vconn_2246, target_1, target_2, target_3)
and func_1(target_2, target_1)
and func_2(vconn_2246, target_2)
and func_3(vconn_2246, target_3)
and vconn_2246.getType().hasName("PGconn *")
and vconn_2246.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
