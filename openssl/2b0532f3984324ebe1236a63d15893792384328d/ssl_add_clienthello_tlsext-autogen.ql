/**
 * @name openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_add_clienthello_tlsext
 * @id cpp/openssl/2b0532f3984324ebe1236a63d15893792384328d/ssl-add-clienthello-tlsext
 * @description openssl-2b0532f3984324ebe1236a63d15893792384328d-ssl_add_clienthello_tlsext CVE-2014-3513
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vel_648, Parameter vs_355) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="version"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="method"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_355
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65279"
		and target_0.getAnOperand() instanceof FunctionCall
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ssl_add_clienthello_use_srtp_ext")
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_355
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vel_648
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="0")
}

predicate func_1(Parameter vs_355) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("SSL_get_srtp_profiles")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vs_355)
}

predicate func_2(Parameter vs_355) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="tmp"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_355)
}

from Function func, Variable vel_648, Parameter vs_355
where
not func_0(vel_648, vs_355)
and func_1(vs_355)
and vel_648.getType().hasName("int")
and vs_355.getType().hasName("SSL *")
and func_2(vs_355)
and vel_648.getParentScope+() = func
and vs_355.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
