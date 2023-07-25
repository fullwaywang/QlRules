/**
 * @name postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-makeEmptyPGconn
 * @id cpp/postgresql/d1c6a14bacfa5fe7690e2c71b1626dbc87a57355/makeEmptyPGconn
 * @description postgresql-d1c6a14bacfa5fe7690e2c71b1626dbc87a57355-src/interfaces/libpq/fe-connect.c-makeEmptyPGconn CVE-2018-10915
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_3314, Function func, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="auth_req_received"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3314
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

predicate func_1(Variable vconn_3314, Function func, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="password_needed"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3314
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vconn_3314, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pgpassfile_used"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_3314
		and target_2.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vconn_3314, ExprStmt target_0, ExprStmt target_1, ExprStmt target_2
where
func_0(vconn_3314, func, target_0)
and func_1(vconn_3314, func, target_1)
and func_2(vconn_3314, func, target_2)
and vconn_3314.getType().hasName("PGconn *")
and vconn_3314.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
