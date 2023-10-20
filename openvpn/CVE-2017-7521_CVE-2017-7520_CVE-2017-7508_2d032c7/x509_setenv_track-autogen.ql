/**
 * @name openvpn-2d032c7fcd-x509_setenv_track
 * @id cpp/openvpn/2d032c7fcd/x509-setenv-track
 * @description openvpn-2d032c7fcd-src/openvpn/ssl_verify_openssl.c-x509_setenv_track CVE-2017-7508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand() instanceof FunctionCall
		and target_0.getLesserOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vval_467, Variable vbuf_468, FunctionCall target_1) {
		target_1.getTarget().hasName("ASN1_STRING_to_UTF8")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_468
		and target_1.getArgument(1).(VariableAccess).getTarget()=vval_467
}

predicate func_3(BlockStmt target_4, Function func, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand() instanceof FunctionCall
		and target_3.getLesserOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vbuf_468, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("do_setenv_x509")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="name"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbuf_468
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CRYPTO_free")
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_468
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
}

from Function func, Variable vval_467, Variable vbuf_468, FunctionCall target_1, RelationalOperation target_3, BlockStmt target_4
where
not func_0(target_4, func)
and func_1(vval_467, vbuf_468, target_1)
and func_3(target_4, func, target_3)
and func_4(vbuf_468, target_4)
and vval_467.getType().hasName("ASN1_STRING *")
and vbuf_468.getType().hasName("unsigned char *")
and vval_467.getParentScope+() = func
and vbuf_468.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
