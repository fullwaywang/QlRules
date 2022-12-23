/**
 * @name linux-3c4e0dff2095c579b142d5a0693257f1c58b4804-con_font_op
 * @id cpp/linux/3c4e0dff2095c579b142d5a0693257f1c58b4804/con_font_op
 * @description linux-3c4e0dff2095c579b142d5a0693257f1c58b4804-con_font_op 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(UnaryMinusExpr target_0 |
		target_0.getValue()="-22"
		and target_0.getOperand().(Literal).getValue()="22"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vvc_4728, Parameter vop_4728) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("con_font_copy")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vvc_4728
		and target_1.getArgument(1).(VariableAccess).getTarget()=vop_4728)
}

from Function func, Parameter vvc_4728, Parameter vop_4728
where
not func_0(func)
and func_1(vvc_4728, vop_4728)
and vvc_4728.getType().hasName("vc_data *")
and vop_4728.getType().hasName("console_font_op *")
and vvc_4728.getParentScope+() = func
and vop_4728.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
