/**
 * @name libxml2-e2a9122b8dde53d320750451e9907a7dcb2ca8bb-xz_head
 * @id cpp/libxml2/e2a9122b8dde53d320750451e9907a7dcb2ca8bb/xz-head
 * @description libxml2-e2a9122b8dde53d320750451e9907a7dcb2ca8bb-xzlib.c-xz_head CVE-2017-18258
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="18446744073709551615"
		and not target_0.getValue()="100000000"
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("lzma_auto_decoder")
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="strm"
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("xz_statep")
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getEnclosingFunction() = func
}

from Function func, Literal target_0
where
func_0(func, target_0)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
