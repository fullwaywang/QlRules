/**
 * @name linux-9f645bcc566a1e9f921bdae7528a01ced5bc3713-uvesafb_setcmap
 * @id cpp/linux/9f645bcc566a1e9f921bdae7528a01ced5bc3713/uvesafb-setcmap
 * @description linux-9f645bcc566a1e9f921bdae7528a01ced5bc3713-uvesafb_setcmap 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("kmalloc")
		and not target_0.getTarget().hasName("kmalloc_array")
		and target_0.getArgument(0).(MulExpr).getLeftOperand() instanceof SizeofExprOperator
		and target_0.getArgument(0).(MulExpr).getRightOperand() instanceof PointerFieldAccess
		and target_0.getArgument(1).(BitwiseOrExpr).getValue()="6291648"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="6291520"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="6291456"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="2097152"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="4194304"
		and target_0.getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="64"
		and target_0.getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable ventries_1038) {
	exists(SizeofExprOperator target_1 |
		target_1.getValue()="4"
		and target_1.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ventries_1038)
}

predicate func_2(Parameter vcmap_1036) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="len"
		and target_2.getQualifier().(VariableAccess).getTarget()=vcmap_1036)
}

from Function func, Parameter vcmap_1036, Variable ventries_1038
where
func_0(func)
and func_1(ventries_1038)
and func_2(vcmap_1036)
and vcmap_1036.getType().hasName("fb_cmap *")
and ventries_1038.getType().hasName("uvesafb_pal_entry *")
and vcmap_1036.getParentScope+() = func
and ventries_1038.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
