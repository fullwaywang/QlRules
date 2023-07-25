/**
 * @name bluez-35d8d895cd0b724e58129374beb0bb4a2edf9519-hog_accept
 * @id cpp/bluez/35d8d895cd0b724e58129374beb0bb4a2edf9519/hog-accept
 * @description bluez-35d8d895cd0b724e58129374beb0bb4a2edf9519-profiles/input/hog.c-hog_accept CVE-2020-0556
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdevice_179, NotExpr target_3, FunctionCall target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bt_gatt_client *")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("btd_device_get_gatt_client")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdevice_179
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(NotExpr target_3, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("bt_gatt_client_set_security")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("bt_gatt_client *")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="2"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ReturnStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(NotExpr target_3, Function func, ReturnStmt target_2) {
		target_2.getExpr().(UnaryMinusExpr).getValue()="-111"
		and target_2.getParent().(IfStmt).getCondition()=target_3
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vdevice_179, NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("device_is_bonded")
		and target_3.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdevice_179
		and target_3.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("btd_device_get_bdaddr_type")
		and target_3.getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdevice_179
}

predicate func_4(Variable vdevice_179, FunctionCall target_4) {
		target_4.getTarget().hasName("btd_device_get_bdaddr_type")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vdevice_179
}

from Function func, Variable vdevice_179, ReturnStmt target_2, NotExpr target_3, FunctionCall target_4
where
not func_0(vdevice_179, target_3, target_4)
and not func_1(target_3, func)
and func_2(target_3, func, target_2)
and func_3(vdevice_179, target_3)
and func_4(vdevice_179, target_4)
and vdevice_179.getType().hasName("btd_device *")
and vdevice_179.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
