/**
 * @name bluez-8cdbd3b09f29da29374e2f83369df24228da0ad1-hog_accept
 * @id cpp/bluez/8cdbd3b09f29da29374e2f83369df24228da0ad1/hog-accept
 * @description bluez-8cdbd3b09f29da29374e2f83369df24228da0ad1-profiles/input/hog.c-hog_accept CVE-2020-0556
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdevice_179, FunctionCall target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("device_is_bonded")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdevice_179
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getTarget().hasName("btd_device_get_bdaddr_type")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdevice_179
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-111"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_1.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdevice_179, FunctionCall target_1) {
		target_1.getTarget().hasName("btd_device_get_attrib")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdevice_179
}

from Function func, Variable vdevice_179, FunctionCall target_1
where
not func_0(vdevice_179, target_1, func)
and func_1(vdevice_179, target_1)
and vdevice_179.getType().hasName("btd_device *")
and vdevice_179.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
