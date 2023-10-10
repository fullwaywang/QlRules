/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-move_next_session
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/move-next-session
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/iter.c-move_next_session CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter viter_512, FunctionCall target_0) {
		target_0.getTarget().hasName("realloc")
		and not target_0.getTarget().hasName("reallocarray")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="slots"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=viter_512
		and target_0.getArgument(1).(MulExpr).getLeftOperand() instanceof SizeofTypeOperator
		and target_0.getArgument(1).(MulExpr).getRightOperand() instanceof AddExpr
}

predicate func_1(Variable vnum_slots_515, AddExpr target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vnum_slots_515
		and target_1.getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="8"
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vnum_slots_515, Parameter viter_512, FunctionCall target_0, AddExpr target_1, SizeofTypeOperator target_2
where
func_0(viter_512, target_0)
and func_1(vnum_slots_515, target_1)
and func_2(func, target_2)
and vnum_slots_515.getType().hasName("CK_ULONG")
and viter_512.getType().hasName("P11KitIter *")
and vnum_slots_515.getParentScope+() = func
and viter_512.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
