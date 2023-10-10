/**
 * @name freerdp-733ee3208306b1ea32697b356c0215180fc3f049-update_prepare_order_info
 * @id cpp/freerdp/733ee3208306b1ea32697b356c0215180fc3f049/update-prepare-order-info
 * @description freerdp-733ee3208306b1ea32697b356c0215180fc3f049-libfreerdp/core/update.c-update_prepare_order_info CVE-2020-11095
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vorderInfo_1082, ExprStmt target_3, ExprStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_primary_drawing_order_field_bytes")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="orderType"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1082
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vorderInfo_1082, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="orderType"
		and target_1.getQualifier().(VariableAccess).getTarget()=vorderInfo_1082
		and target_1.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
}

predicate func_2(Parameter vorderInfo_1082, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
		and target_2.getArrayOffset().(PointerFieldAccess).getTarget().getName()="orderType"
		and target_2.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1082
		and target_2.getParent().(AssignAddExpr).getRValue() = target_2
}

predicate func_3(Parameter vorderInfo_1082, ExprStmt target_3) {
		target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="controlFlags"
		and target_3.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1082
		and target_3.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="8"
}

predicate func_4(Parameter vorderInfo_1082, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("update_prepare_bounds")
		and target_4.getExpr().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorderInfo_1082
}

from Function func, Parameter vorderInfo_1082, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_1, ArrayExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vorderInfo_1082, target_3, target_4)
and func_1(vorderInfo_1082, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_1)
and func_2(vorderInfo_1082, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_2)
and func_3(vorderInfo_1082, target_3)
and func_4(vorderInfo_1082, target_4)
and vorderInfo_1082.getType().hasName("ORDER_INFO *")
and vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getType() instanceof ArrayType
and vorderInfo_1082.getParentScope+() = func
and not vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
