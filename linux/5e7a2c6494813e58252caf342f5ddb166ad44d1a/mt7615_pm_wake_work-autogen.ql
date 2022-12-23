/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7615_pm_wake_work
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7615-pm-wake-work
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7615_pm_wake_work CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdev_1901, Variable vmphy_1902) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("test_bit")
		and target_0.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_0.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1902
		and target_0.getThen() instanceof ExprStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="set_drv_ctrl"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mcu_ops"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1901
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdev_1901)
}

predicate func_1(Variable vdev_1901, Variable vmphy_1902) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ieee80211_queue_delayed_work")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="hw"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1902
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mac_work"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmphy_1902
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getValue()="25"
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getLeftOperand().(Literal).getValue()="250"
		and target_1.getExpr().(FunctionCall).getArgument(2).(DivExpr).getRightOperand().(Literal).getValue()="10"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="set_drv_ctrl"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mcu_ops"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1901
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vdev_1901)
}

predicate func_2(Variable vdev_1901, Variable vmphy_1902) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("mt76_connac_pm_dequeue_skbs")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vmphy_1902
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="pm"
		and target_2.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1901)
}

from Function func, Variable vdev_1901, Variable vmphy_1902
where
not func_0(vdev_1901, vmphy_1902)
and func_1(vdev_1901, vmphy_1902)
and vdev_1901.getType().hasName("mt7615_dev *")
and vmphy_1902.getType().hasName("mt76_phy *")
and func_2(vdev_1901, vmphy_1902)
and vdev_1901.getParentScope+() = func
and vmphy_1902.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
