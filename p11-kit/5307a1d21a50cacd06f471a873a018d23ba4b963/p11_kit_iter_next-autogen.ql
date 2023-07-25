/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11_kit_iter_next
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/p11-kit-iter-next
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/iter.c-p11_kit_iter_next CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viter_631, FunctionCall target_0) {
		target_0.getTarget().hasName("realloc")
		and not target_0.getTarget().hasName("reallocarray")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="objects"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_631
		and target_0.getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="max_objects"
		and target_0.getArgument(1).(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_631
		and target_0.getArgument(1).(MulExpr).getRightOperand() instanceof SizeofTypeOperator
}

predicate func_1(Parameter viter_631, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="max_objects"
		and target_1.getQualifier().(VariableAccess).getTarget()=viter_631
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="8"
		and target_2.getEnclosingFunction() = func
}

from Function func, Parameter viter_631, FunctionCall target_0, PointerFieldAccess target_1, SizeofTypeOperator target_2
where
func_0(viter_631, target_0)
and func_1(viter_631, target_1)
and func_2(func, target_2)
and viter_631.getType().hasName("P11KitIter *")
and viter_631.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
