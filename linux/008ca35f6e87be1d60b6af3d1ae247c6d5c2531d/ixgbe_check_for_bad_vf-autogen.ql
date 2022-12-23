/**
 * @name linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_check_for_bad_vf
 * @id cpp/linux/008ca35f6e87be1d60b6af3d1ae247c6d5c2531d/ixgbe_check_for_bad_vf
 * @description linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_check_for_bad_vf CVE-2021-33061
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vadapter_7616, Variable vvf_7620, Variable vstatus_reg_7641) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("ixgbe_bad_vf_abort")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vadapter_7616
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvf_7620
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_reg_7641
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65535"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vstatus_reg_7641
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8192")
}

predicate func_1(Variable vvfdev_7640, Variable vstatus_reg_7641) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("pcie_flr")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvfdev_7640
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vstatus_reg_7641
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="65535"
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vstatus_reg_7641
		and target_1.getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="8192")
}

predicate func_2(Parameter vadapter_7616) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="vfinfo"
		and target_2.getQualifier().(VariableAccess).getTarget()=vadapter_7616)
}

predicate func_3(Parameter vadapter_7616, Variable vvf_7620) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(PointerFieldAccess).getTarget().getName()="vfinfo"
		and target_3.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_7616
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vvf_7620)
}

from Function func, Parameter vadapter_7616, Variable vvf_7620, Variable vvfdev_7640, Variable vstatus_reg_7641
where
not func_0(vadapter_7616, vvf_7620, vstatus_reg_7641)
and func_1(vvfdev_7640, vstatus_reg_7641)
and vadapter_7616.getType().hasName("ixgbe_adapter *")
and func_2(vadapter_7616)
and vvf_7620.getType().hasName("unsigned int")
and func_3(vadapter_7616, vvf_7620)
and vvfdev_7640.getType().hasName("pci_dev *")
and vstatus_reg_7641.getType().hasName("u16")
and vadapter_7616.getParentScope+() = func
and vvf_7620.getParentScope+() = func
and vvfdev_7640.getParentScope+() = func
and vstatus_reg_7641.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
