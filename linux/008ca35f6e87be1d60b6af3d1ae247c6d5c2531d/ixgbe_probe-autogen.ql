/**
 * @name linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_probe
 * @id cpp/linux/008ca35f6e87be1d60b6af3d1ae247c6d5c2531d/ixgbe_probe
 * @description linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_probe CVE-2021-33061
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vadapter_10633, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="type"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="mac"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="hw"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_10633
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="flags2"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_10633
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="524288"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="19"
		and func.getEntryPoint().(BlockStmt).getStmt(55)=target_0)
}

predicate func_1(Variable vadapter_10633, Variable vii_10635) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ixgbe_sw_init")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vadapter_10633
		and target_1.getArgument(1).(VariableAccess).getTarget()=vii_10635)
}

from Function func, Variable vadapter_10633, Variable vii_10635
where
not func_0(vadapter_10633, func)
and vadapter_10633.getType().hasName("ixgbe_adapter *")
and func_1(vadapter_10633, vii_10635)
and vii_10635.getType().hasName("const ixgbe_info *")
and vadapter_10633.getParentScope+() = func
and vii_10635.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
