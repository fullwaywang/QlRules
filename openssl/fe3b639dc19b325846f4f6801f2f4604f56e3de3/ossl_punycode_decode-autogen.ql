/**
 * @name openssl-fe3b639dc19b325846f4f6801f2f4604f56e3de3-ossl_punycode_decode
 * @id cpp/openssl/fe3b639dc19b325846f4f6801f2f4604f56e3de3/ossl-punycode-decode
 * @description openssl-fe3b639dc19b325846f4f6801f2f4604f56e3de3-ossl_punycode_decode CVE-2022-3602
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwritten_out_124, Variable vmax_out_125) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vwritten_out_124
		and target_0.getLesserOperand().(VariableAccess).getTarget()=vmax_out_125
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

predicate func_3(Variable vwritten_out_124, Variable vmax_out_125) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vwritten_out_124
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vmax_out_125
		and target_3.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Variable vwritten_out_124, Variable vmax_out_125
where
not func_0(vwritten_out_124, vmax_out_125)
and func_3(vwritten_out_124, vmax_out_125)
and vwritten_out_124.getType().hasName("size_t")
and vmax_out_125.getType().hasName("unsigned int")
and vwritten_out_124.getParentScope+() = func
and vmax_out_125.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
