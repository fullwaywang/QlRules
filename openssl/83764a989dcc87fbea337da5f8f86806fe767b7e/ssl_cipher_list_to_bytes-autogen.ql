/**
 * @name openssl-83764a989dcc87fbea337da5f8f86806fe767b7e-ssl_cipher_list_to_bytes
 * @id cpp/openssl/83764a989dcc87fbea337da5f8f86806fe767b7e/ssl-cipher-list-to-bytes
 * @description openssl-83764a989dcc87fbea337da5f8f86806fe767b7e-ssl_cipher_list_to_bytes CVE-2014-5139
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_1378, Variable vc_1382) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_mkey"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1382
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_auth"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1382
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="srp_Mask"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="srp_ctx"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1378
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="1024"
		and target_0.getThen().(ContinueStmt).toString() = "continue;")
}

predicate func_1(Parameter vs_1378, Variable vc_1382) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_mkey"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1382
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="256"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="algorithm_auth"
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_1382
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="psk_client_callback"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1378
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen().(ContinueStmt).toString() = "continue;")
}

from Function func, Parameter vs_1378, Variable vc_1382
where
not func_0(vs_1378, vc_1382)
and vs_1378.getType().hasName("SSL *")
and func_1(vs_1378, vc_1382)
and vc_1382.getType().hasName("SSL_CIPHER *")
and vs_1378.getParentScope+() = func
and vc_1382.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
