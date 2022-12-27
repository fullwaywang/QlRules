/**
 * @name libxml2-5dca9eea1bd4263bfa4d037ab2443de1cd730f7e-xmlNanoHTTPMethodRedir__internal_alias
 * @id cpp/libxml2/5dca9eea1bd4263bfa4d037ab2443de1cd730f7e/xmlNanoHTTPMethodRedir--internal-alias
 * @description libxml2-5dca9eea1bd4263bfa4d037ab2443de1cd730f7e-xmlNanoHTTPMethodRedir__internal_alias CVE-2017-7376
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vblen_1353) {
	exists(Literal target_0 |
		target_0.getValue()="12"
		and not target_0.getValue()="17"
		and target_0.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vblen_1353)
}

predicate func_1(Variable vblen_1353) {
	exists(Literal target_1 |
		target_1.getValue()="6"
		and not target_1.getValue()="11"
		and target_1.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vblen_1353)
}

from Function func, Variable vblen_1353
where
func_0(vblen_1353)
and func_1(vblen_1353)
and vblen_1353.getType().hasName("int")
and vblen_1353.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
