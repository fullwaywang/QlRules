/**
 * @name freerdp-733ee3208306b1ea32697b356c0215180fc3f049-update_write_order_info
 * @id cpp/freerdp/733ee3208306b1ea32697b356c0215180fc3f049/update-write-order-info
 * @description freerdp-733ee3208306b1ea32697b356c0215180fc3f049-libfreerdp/core/update.c-update_write_order_info CVE-2020-11095
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vorderInfo_1095, ExprStmt target_3, ExprStmt target_4) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("get_primary_drawing_order_field_bytes")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="orderType"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_0.getArgument(1).(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vorderInfo_1095, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="orderType"
		and target_1.getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_1.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
}

predicate func_2(Parameter vorderInfo_1095, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, ArrayExpr target_2) {
		target_2.getArrayBase().(VariableAccess).getTarget()=vPRIMARY_DRAWING_ORDER_FIELD_BYTES
		and target_2.getArrayOffset().(PointerFieldAccess).getTarget().getName()="orderType"
		and target_2.getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("update_write_field_flags")
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="controlFlags"
		and target_2.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
}

predicate func_3(Parameter vorderInfo_1095, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("update_write_field_flags")
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fieldFlags"
		and target_3.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="controlFlags"
		and target_3.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vorderInfo_1095
		and target_3.getExpr().(FunctionCall).getArgument(3) instanceof ArrayExpr
}

predicate func_4(Parameter vorderInfo_1095, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("update_write_bounds")
		and target_4.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vorderInfo_1095
}

from Function func, Parameter vorderInfo_1095, Variable vPRIMARY_DRAWING_ORDER_FIELD_BYTES, PointerFieldAccess target_1, ArrayExpr target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vorderInfo_1095, target_3, target_4)
and func_1(vorderInfo_1095, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_1)
and func_2(vorderInfo_1095, vPRIMARY_DRAWING_ORDER_FIELD_BYTES, target_2)
and func_3(vorderInfo_1095, target_3)
and func_4(vorderInfo_1095, target_4)
and vorderInfo_1095.getType().hasName("ORDER_INFO *")
and vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getType() instanceof ArrayType
and vorderInfo_1095.getParentScope+() = func
and not vPRIMARY_DRAWING_ORDER_FIELD_BYTES.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
