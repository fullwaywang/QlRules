/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7663u_mcu_init
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7663u-mcu-init
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7663u_mcu_init CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(CommaExpr target_0 |
		target_0.getLeftOperand() instanceof AssignExpr
		and target_0.getRightOperand() instanceof VariableCall
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdev_45, Variable vmt7663u_mcu_ops_47) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(ValueFieldAccess).getTarget().getName()="mcu_ops"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_1.getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_45
		and target_1.getRValue().(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmt7663u_mcu_ops_47)
}

predicate func_2(Parameter vdev_45) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(ValueFieldAccess).getTarget().getName()="state"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mphy"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_2.getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_45
		and target_2.getParent().(FunctionCall).getParent().(CommaExpr).getRightOperand() instanceof FunctionCall)
}

predicate func_3(Parameter vdev_45) {
	exists(VariableCall target_3 |
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="rmw"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="bus"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_45
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mt76"
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_3.getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_45
		and target_3.getArgument(1).(AddExpr).getValue()="2080374792"
		and target_3.getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="2080374784"
		and target_3.getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_3.getArgument(2).(Literal).getValue()="0"
		and target_3.getArgument(3).(BinaryBitwiseOperation).getValue()="8"
		and target_3.getArgument(3).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_3.getArgument(3).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="3")
}

predicate func_4(Function func) {
	exists(CommaExpr target_4 |
		target_4.getLeftOperand() instanceof AssignExpr
		and target_4.getRightOperand().(FunctionCall).getTarget().hasName("clear_bit")
		and target_4.getRightOperand().(FunctionCall).getArgument(1) instanceof AddressOfExpr
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr() instanceof VariableCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_5)
}

from Function func, Parameter vdev_45, Variable vmt7663u_mcu_ops_47
where
not func_0(func)
and func_1(vdev_45, vmt7663u_mcu_ops_47)
and func_2(vdev_45)
and func_3(vdev_45)
and func_4(func)
and func_5(func)
and vdev_45.getType().hasName("mt7615_dev *")
and vmt7663u_mcu_ops_47.getType().hasName("const mt76_mcu_ops")
and vdev_45.getParentScope+() = func
and vmt7663u_mcu_ops_47.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
