/**
 * @name openssl-80bd7b41b30af6ee96f519e629463583318de3b0-ssl_set_client_disabled
 * @id cpp/openssl/80bd7b41b30af6ee96f519e629463583318de3b0/ssl-set-client-disabled
 * @description openssl-80bd7b41b30af6ee96f519e629463583318de3b0-ssl_set_client_disabled CVE-2014-2970
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1056, Variable vc_1058, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="srp_Mask"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="srp_ctx"
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1056
		and target_0.getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mask_a"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1058
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1024"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mask_k"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1058
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="1024"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vs_1056, Variable vc_1058) {
	exists(NotExpr target_3 |
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="psk_client_callback"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1056
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mask_a"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1058
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mask_k"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1058
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="256")
}

predicate func_4(Variable vc_1058) {
	exists(AssignOrExpr target_4 |
		target_4.getLValue().(PointerFieldAccess).getTarget().getName()="mask_k"
		and target_4.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1058
		and target_4.getRValue().(Literal).getValue()="256")
}

from Function func, Parameter vs_1056, Variable vc_1058
where
not func_0(vs_1056, vc_1058, func)
and vs_1056.getType().hasName("SSL *")
and func_3(vs_1056, vc_1058)
and vc_1058.getType().hasName("CERT *")
and func_4(vc_1058)
and vs_1056.getParentScope+() = func
and vc_1058.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
