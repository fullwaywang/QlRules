/**
 * @name libxml2-5dca9eea1bd4263bfa4d037ab2443de1cd730f7e-xmlNanoHTTPMethodRedir__internal_alias
 * @id cpp/libxml2/5dca9eea1bd4263bfa4d037ab2443de1cd730f7e/xmlNanoHTTPMethodRedir--internal-alias
 * @description libxml2-5dca9eea1bd4263bfa4d037ab2443de1cd730f7e-nanohttp.c-xmlNanoHTTPMethodRedir__internal_alias CVE-2017-7376
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="12"
		and not target_0.getValue()="17"
		and target_0.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="6"
		and not target_1.getValue()="11"
		and target_1.getParent().(AssignAddExpr).getParent().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_1.getEnclosingFunction() = func
}

from Function func, Literal target_0, Literal target_1
where
func_0(func, target_0)
and func_1(func, target_1)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
