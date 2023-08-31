/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-connectDBStart
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/connectDBStart
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-connectDBStart CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_0(Parameter vconn_1687, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="send_appname"
		and target_0.getQualifier().(VariableAccess).getTarget()=vconn_1687
}

*/
predicate func_1(Parameter vconn_1687, ExprStmt target_12, Literal target_1) {
		target_1.getValue()="1"
		and not target_1.getValue()="0"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="send_appname"
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_1.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Parameter vconn_1687, ExprStmt target_13, Literal target_2) {
		target_2.getValue()="0"
		and not target_2.getValue()="1"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_3(Function func, Literal target_3) {
		target_3.getValue()="0"
		and not target_3.getValue()="1"
		and target_3.getParent().(ArrayExpr).getParent().(ValueFieldAccess).getQualifier() instanceof ArrayExpr
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vconn_1687, ExprStmt target_15) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("resetPQExpBuffer")
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="errorMessage"
		and target_4.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vconn_1687) {
	exists(UnaryMinusExpr target_5 |
		target_5.getValue()="-1"
		and target_5.getParent().(AssignExpr).getRValue() = target_5
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_5.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687)
}

predicate func_6(Parameter vconn_1687) {
	exists(AssignExpr target_6 |
		target_6.getLValue().(PointerFieldAccess).getTarget().getName()="try_next_host"
		and target_6.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_6.getRValue().(Literal).getValue()="1")
}

predicate func_7(Parameter vconn_1687, VariableAccess target_7) {
		target_7.getTarget()=vconn_1687
}

predicate func_8(Parameter vconn_1687, VariableAccess target_8) {
		target_8.getTarget()=vconn_1687
}

predicate func_9(Parameter vconn_1687, AssignExpr target_9) {
		target_9.getLValue().(PointerFieldAccess).getTarget().getName()="addr_cur"
		and target_9.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_9.getRValue().(ValueFieldAccess).getTarget().getName()="addrlist"
		and target_9.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="connhost"
		and target_9.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_9.getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_10(Parameter vconn_1687, AssignExpr target_10) {
		target_10.getLValue().(PointerFieldAccess).getTarget().getName()="pversion"
		and target_10.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_10.getRValue().(BitwiseOrExpr).getValue()="196608"
}

predicate func_12(Parameter vconn_1687, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
}

predicate func_13(Parameter vconn_1687, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="options_valid"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_15(Parameter vconn_1687, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_1687
		and target_15.getExpr().(AssignExpr).getRValue() instanceof Literal
}

from Function func, Parameter vconn_1687, Literal target_1, Literal target_2, Literal target_3, VariableAccess target_7, VariableAccess target_8, AssignExpr target_9, AssignExpr target_10, ExprStmt target_12, ExprStmt target_13, ExprStmt target_15
where
func_1(vconn_1687, target_12, target_1)
and func_2(vconn_1687, target_13, target_2)
and func_3(func, target_3)
and not func_4(vconn_1687, target_15)
and not func_5(vconn_1687)
and not func_6(vconn_1687)
and func_7(vconn_1687, target_7)
and func_8(vconn_1687, target_8)
and func_9(vconn_1687, target_9)
and func_10(vconn_1687, target_10)
and func_12(vconn_1687, target_12)
and func_13(vconn_1687, target_13)
and func_15(vconn_1687, target_15)
and vconn_1687.getType().hasName("PGconn *")
and vconn_1687.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
