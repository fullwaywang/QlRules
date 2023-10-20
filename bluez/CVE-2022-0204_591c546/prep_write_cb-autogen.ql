/**
 * @name bluez-591c546c536b42bef696d027f64aa22434f8c3f0-prep_write_cb
 * @id cpp/bluez/591c546c536b42bef696d027f64aa22434f8c3f0/prep-write-cb
 * @description bluez-591c546c536b42bef696d027f64aa22434f8c3f0-src/shared/gatt-server.c-prep_write_cb CVE-2022-0204
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlength_1270, Variable voffset_1275, Variable vecode_1278, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vecode_1278
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("check_length")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlength_1270
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_1275
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_2.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vecode_1278, IfStmt target_7, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vecode_1278
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and target_1.getThen().(GotoStmt).getName() ="error"
		and (func.getEntryPoint().(BlockStmt).getStmt(16)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(16).getFollowingStmt()=target_1)
		and target_7.getCondition().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vlength_1270, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vlength_1270
		and target_2.getGreaterOperand().(Literal).getValue()="4"
}

predicate func_3(Parameter vlength_1270, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pdu"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("malloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlength_1270
}

predicate func_4(Variable voffset_1275, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1275
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_le16")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="2"
}

predicate func_5(Variable voffset_1275, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("gatt_db_attribute_write")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_1275
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="22"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="att"
}

predicate func_6(Variable vecode_1278, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vecode_1278
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_7(Variable vecode_1278, IfStmt target_7) {
		target_7.getCondition().(VariableAccess).getTarget()=vecode_1278
		and target_7.getThen().(GotoStmt).toString() = "goto ..."
		and target_7.getThen().(GotoStmt).getName() ="error"
}

from Function func, Parameter vlength_1270, Variable voffset_1275, Variable vecode_1278, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, IfStmt target_7
where
not func_0(vlength_1270, voffset_1275, vecode_1278, target_2, target_3, target_4, target_5, target_6, func)
and not func_1(vecode_1278, target_7, func)
and func_2(vlength_1270, target_2)
and func_3(vlength_1270, target_3)
and func_4(voffset_1275, target_4)
and func_5(voffset_1275, target_5)
and func_6(vecode_1278, target_6)
and func_7(vecode_1278, target_7)
and vlength_1270.getType().hasName("uint16_t")
and voffset_1275.getType().hasName("uint16_t")
and vecode_1278.getType().hasName("uint8_t")
and vlength_1270.getParentScope+() = func
and voffset_1275.getParentScope+() = func
and vecode_1278.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
