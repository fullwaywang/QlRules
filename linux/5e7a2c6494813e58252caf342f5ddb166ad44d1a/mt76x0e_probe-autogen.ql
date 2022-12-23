/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt76x0e_probe
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt76x0e-probe
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt76x0e_probe CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpdev_136, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("mt76_pci_disable_aspm")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpdev_136
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vpdev_136) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("pci_set_dma_mask")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vpdev_136
		and target_1.getArgument(1).(ConditionalExpr).getValue()="4294967295"
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getValue()="0"
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="32"
		and target_1.getArgument(1).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="64"
		and target_1.getArgument(1).(ConditionalExpr).getThen().(ComplementExpr).getValue()="18446744073709551615"
		and target_1.getArgument(1).(ConditionalExpr).getThen().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(SubExpr).getValue()="4294967295"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getValue()="4294967296"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="32"
		and target_1.getArgument(1).(ConditionalExpr).getElse().(SubExpr).getRightOperand().(Literal).getValue()="1")
}

from Function func, Parameter vpdev_136
where
not func_0(vpdev_136, func)
and vpdev_136.getType().hasName("pci_dev *")
and func_1(vpdev_136)
and vpdev_136.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
