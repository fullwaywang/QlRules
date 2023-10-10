/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_pm_wake_work
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7921-pm-wake-work
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_pm_wake_work CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_1393, Variable vmphy_1394) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("test_bit")
		and target_0.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1394
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mt7921_mcu_drv_pmctrl")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_1393)
}

predicate func_1(Variable vdev_1393, Variable vmphy_1394) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ieee80211_queue_delayed_work")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1394
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mac_work"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1394
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getValue()="62"
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(Literal).getValue()="250"
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="4"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mt7921_mcu_drv_pmctrl")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdev_1393)
}

predicate func_2(Variable vdev_1393, Variable vmphy_1394) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("mt76_connac_pm_dequeue_skbs")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vmphy_1394
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pm"
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1393)
}

from Function func, Variable vdev_1393, Variable vmphy_1394
where
not func_0(vdev_1393, vmphy_1394)
and func_1(vdev_1393, vmphy_1394)
and vdev_1393.getType().hasName("mt7921_dev *")
and vmphy_1394.getType().hasName("mt76_phy *")
and func_2(vdev_1393, vmphy_1394)
and vdev_1393.getParentScope+() = func
and vmphy_1394.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
