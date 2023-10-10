/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-restoreErrorMessage
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/restoreErrorMessage
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-restoreErrorMessage CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_1966, Parameter vsavedMessage_1966) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsavedMessage_1966
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="maxlen"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsavedMessage_1966
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1966
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="maxlen"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printfPQExpBuffer")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1966
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="out of memory\n")
}

predicate func_1(Parameter vconn_1966, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1966
}

predicate func_2(Parameter vconn_1966, Parameter vsavedMessage_1966, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("appendPQExpBufferStr")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1966
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsavedMessage_1966
}

predicate func_3(Parameter vsavedMessage_1966, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("termPQExpBuffer")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsavedMessage_1966
}

from Function func, Parameter vconn_1966, Parameter vsavedMessage_1966, AddressOfExpr target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vconn_1966, vsavedMessage_1966)
and func_1(vconn_1966, target_1)
and func_2(vconn_1966, vsavedMessage_1966, target_2)
and func_3(vsavedMessage_1966, target_3)
and vconn_1966.getType().hasName("PGconn *")
and vsavedMessage_1966.getType().hasName("PQExpBuffer")
and vconn_1966.getFunction() = func
and vsavedMessage_1966.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
