/**
 * @name libssh2-ca2744483eac4e707084df5fc55cc69d57571dde-userauth_list
 * @id cpp/libssh2/ca2744483eac4e707084df5fc55cc69d57571dde/userauth-list
 * @description libssh2-ca2744483eac4e707084df5fc55cc69d57571dde-src/userauth.c-userauth_list CVE-2019-3859
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrc_72, Parameter vsession_63, BlockStmt target_2, LogicalOrExpr target_0) {
		target_0.getAnOperand().(VariableAccess).getTarget()=vrc_72
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="userauth_list_data_len"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen()=target_2
}

predicate func_1(Variable vrc_72, BlockStmt target_3, VariableAccess target_1) {
		target_1.getTarget()=vrc_72
		and target_1.getParent().(IfStmt).getThen()=target_3
}

predicate func_2(Parameter vsession_63, BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-7"
		and target_2.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Unable to send userauth-none request"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_list_state"
		and target_2.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
}

predicate func_3(Variable vrc_72, Parameter vsession_63, BlockStmt target_3) {
		target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_libssh2_error")
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsession_63
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vrc_72
		and target_3.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Failed getting response"
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="userauth_list_state"
		and target_3.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsession_63
}

from Function func, Variable vrc_72, Parameter vsession_63, LogicalOrExpr target_0, VariableAccess target_1, BlockStmt target_2, BlockStmt target_3
where
func_0(vrc_72, vsession_63, target_2, target_0)
and func_1(vrc_72, target_3, target_1)
and func_2(vsession_63, target_2)
and func_3(vrc_72, vsession_63, target_3)
and vrc_72.getType().hasName("int")
and vsession_63.getType().hasName("LIBSSH2_SESSION *")
and vrc_72.getParentScope+() = func
and vsession_63.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
