/**
 * @name mbedtls-31458a18788b0cf0b722acda9bb2f2fe13a3fb32-x509_crt_verify_child
 * @id cpp/mbedtls/31458a18788b0cf0b722acda9bb2f2fe13a3fb32/x509-crt-verify-child
 * @description mbedtls-31458a18788b0cf0b722acda9bb2f2fe13a3fb32-library/x509_crt.c-x509_crt_verify_child CVE-2017-14032
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, UnaryMinusExpr target_0) {
		target_0.getValue()="-9984"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vflags_2043, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_2043
		and target_1.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getLesserOperand().(Literal).getValue()="8"
}

from Function func, Parameter vflags_2043, UnaryMinusExpr target_0, ExprStmt target_1, RelationalOperation target_2
where
func_0(func, target_0)
and func_1(vflags_2043, target_2, target_1)
and func_2(target_2)
and vflags_2043.getType().hasName("uint32_t *")
and vflags_2043.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
