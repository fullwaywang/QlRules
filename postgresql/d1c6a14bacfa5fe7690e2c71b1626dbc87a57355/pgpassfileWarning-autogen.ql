/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-pgpassfileWarning
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/pgpassfileWarning
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-pgpassfileWarning CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_6504, LogicalAndExpr target_3) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(ValueFieldAccess).getTarget().getName()="password"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="connhost"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_6504
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="whichhost"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_6504
		and target_0.getAnOperand().(Literal).getValue()="0"
		and target_0.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vconn_6504, VariableAccess target_1) {
		target_1.getTarget()=vconn_6504
}

predicate func_2(Parameter vconn_6504, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="pgpassfile_used"
		and target_2.getQualifier().(VariableAccess).getTarget()=vconn_6504
}

predicate func_3(Parameter vconn_6504, LogicalAndExpr target_3) {
		target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="pgpassfile_used"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_6504
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="password_needed"
		and target_3.getAnOperand().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_6504
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="result"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_6504
}

from Function func, Parameter vconn_6504, VariableAccess target_1, PointerFieldAccess target_2, LogicalAndExpr target_3
where
not func_0(vconn_6504, target_3)
and func_1(vconn_6504, target_1)
and func_2(vconn_6504, target_2)
and func_3(vconn_6504, target_3)
and vconn_6504.getType().hasName("PGconn *")
and vconn_6504.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
