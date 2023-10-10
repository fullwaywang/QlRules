/**
 * @name freerdp-907640a924fa7a9a99c80a48ac225e9d8e41548b-update_read_multi_patblt_order
 * @id cpp/freerdp/907640a924fa7a9a99c80a48ac225e9d8e41548b/update-read-multi-patblt-order
 * @description freerdp-907640a924fa7a9a99c80a48ac225e9d8e41548b-libfreerdp/core/orders.c-update_read_multi_patblt_order CVE-2020-11522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmulti_patblt_1257, NotExpr target_3) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("update_read_delta_rects")
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rectangles"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_0.getParent().(FunctionCall).getParent().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vmulti_patblt_1257, VariableAccess target_1) {
		target_1.getTarget()=vmulti_patblt_1257
}

predicate func_2(Parameter vmulti_patblt_1257, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="numRectangles"
		and target_2.getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
}

predicate func_3(Parameter vmulti_patblt_1257, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("update_read_delta_rects")
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rectangles"
		and target_3.getOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
		and target_3.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_3.getOperand().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_patblt_1257
}

from Function func, Parameter vmulti_patblt_1257, VariableAccess target_1, PointerFieldAccess target_2, NotExpr target_3
where
not func_0(vmulti_patblt_1257, target_3)
and func_1(vmulti_patblt_1257, target_1)
and func_2(vmulti_patblt_1257, target_2)
and func_3(vmulti_patblt_1257, target_3)
and vmulti_patblt_1257.getType().hasName("MULTI_PATBLT_ORDER *")
and vmulti_patblt_1257.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
