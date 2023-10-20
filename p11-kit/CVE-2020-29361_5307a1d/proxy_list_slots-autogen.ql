/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-proxy_list_slots
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/proxy-list-slots
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/proxy.c-proxy_list_slots CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpy_251, FunctionCall target_0) {
		target_0.getTarget().hasName("realloc")
		and not target_0.getTarget().hasName("reallocarray")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="mappings"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpy_251
		and target_0.getArgument(1).(MulExpr).getLeftOperand() instanceof SizeofTypeOperator
		and target_0.getArgument(1).(MulExpr).getRightOperand() instanceof AddExpr
}

predicate func_1(Variable vcount_256, Parameter vpy_251, AddExpr target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="n_mappings"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpy_251
		and target_1.getAnOperand().(VariableAccess).getTarget()=vcount_256
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="24"
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vcount_256, Parameter vpy_251, FunctionCall target_0, AddExpr target_1, SizeofTypeOperator target_2
where
func_0(vpy_251, target_0)
and func_1(vcount_256, vpy_251, target_1)
and func_2(func, target_2)
and vcount_256.getType().hasName("CK_ULONG")
and vpy_251.getType().hasName("Proxy *")
and vcount_256.getParentScope+() = func
and vpy_251.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
