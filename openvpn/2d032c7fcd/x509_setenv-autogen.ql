/**
 * @name openvpn-2d032c7fcd-x509_setenv
 * @id cpp/openvpn/2d032c7fcd/x509-setenv
 * @description openvpn-2d032c7fcd-src/openvpn/ssl_verify_openssl.c-x509_setenv CVE-2017-7508
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof FunctionCall
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vval_520, Variable vbuf_523, FunctionCall target_1) {
		target_1.getTarget().hasName("ASN1_STRING_to_UTF8")
		and target_1.getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbuf_523
		and target_1.getArgument(1).(VariableAccess).getTarget()=vval_520
}

predicate func_3(BlockStmt target_4, Function func, RelationalOperation target_3) {
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getLesserOperand() instanceof FunctionCall
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(BlockStmt target_4) {
		target_4.getStmt(0).(ContinueStmt).toString() = "continue;"
}

from Function func, Variable vval_520, Variable vbuf_523, FunctionCall target_1, RelationalOperation target_3, BlockStmt target_4
where
not func_0(target_4, func)
and func_1(vval_520, vbuf_523, target_1)
and func_3(target_4, func, target_3)
and func_4(target_4)
and vval_520.getType().hasName("ASN1_STRING *")
and vbuf_523.getType().hasName("unsigned char *")
and vval_520.getParentScope+() = func
and vbuf_523.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
