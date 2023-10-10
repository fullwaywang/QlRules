/**
 * @name freerdp-907640a924fa7a9a99c80a48ac225e9d8e41548b-update_read_multi_dstblt_order
 * @id cpp/freerdp/907640a924fa7a9a99c80a48ac225e9d8e41548b/update-read-multi-dstblt-order
 * @description freerdp-907640a924fa7a9a99c80a48ac225e9d8e41548b-libfreerdp/core/orders.c-update_read_multi_dstblt_order CVE-2020-11522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vmulti_dstblt_1236, FunctionCall target_3) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
		and target_0.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getTarget().hasName("update_read_delta_rects")
		and target_0.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="rectangles"
		and target_0.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
		and target_0.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_0.getParent().(FunctionCall).getParent().(ReturnStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vmulti_dstblt_1236, VariableAccess target_1) {
		target_1.getTarget()=vmulti_dstblt_1236
}

predicate func_2(Parameter vmulti_dstblt_1236, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="numRectangles"
		and target_2.getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
}

predicate func_3(Parameter vmulti_dstblt_1236, FunctionCall target_3) {
		target_3.getTarget().hasName("update_read_delta_rects")
		and target_3.getArgument(1).(PointerFieldAccess).getTarget().getName()="rectangles"
		and target_3.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
		and target_3.getArgument(2).(PointerFieldAccess).getTarget().getName()="numRectangles"
		and target_3.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmulti_dstblt_1236
}

from Function func, Parameter vmulti_dstblt_1236, VariableAccess target_1, PointerFieldAccess target_2, FunctionCall target_3
where
not func_0(vmulti_dstblt_1236, target_3)
and func_1(vmulti_dstblt_1236, target_1)
and func_2(vmulti_dstblt_1236, target_2)
and func_3(vmulti_dstblt_1236, target_3)
and vmulti_dstblt_1236.getType().hasName("MULTI_DSTBLT_ORDER *")
and vmulti_dstblt_1236.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
