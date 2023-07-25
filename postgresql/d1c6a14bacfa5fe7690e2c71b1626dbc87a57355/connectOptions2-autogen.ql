/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-connectOptions2
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/connectOptions2
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-connectOptions2 CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_896, Variable vi_898, IfStmt target_0) {
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="password"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="connhost"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_896
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_898
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pgpassfile_used"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_896
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vconn_896, Variable vi_898, IfStmt target_0
where
func_0(vconn_896, vi_898, target_0)
and vconn_896.getType().hasName("PGconn *")
and vi_898.getType().hasName("int")
and vconn_896.getFunction() = func
and vi_898.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
