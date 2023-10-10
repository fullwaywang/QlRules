/**
 * @name linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_get_priv_flags
 * @id cpp/linux/008ca35f6e87be1d60b6af3d1ae247c6d5c2531d/ixgbe_get_priv_flags
 * @description linux-008ca35f6e87be1d60b6af3d1ae247c6d5c2531d-ixgbe_get_priv_flags CVE-2021-33061
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vadapter_3504, Variable vpriv_flags_3505, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags2"
		and target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadapter_3504
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="524288"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="19"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(VariableAccess).getTarget()=vpriv_flags_3505
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getValue()="4"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and func.getEntryPoint().(BlockStmt).getStmt(4)=target_0)
}

predicate func_1(Variable vadapter_3504) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="flags2"
		and target_1.getQualifier().(VariableAccess).getTarget()=vadapter_3504)
}

predicate func_2(Variable vpriv_flags_3505, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(VariableAccess).getTarget()=vpriv_flags_3505
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Variable vadapter_3504, Variable vpriv_flags_3505
where
not func_0(vadapter_3504, vpriv_flags_3505, func)
and vadapter_3504.getType().hasName("ixgbe_adapter *")
and func_1(vadapter_3504)
and vpriv_flags_3505.getType().hasName("u32")
and func_2(vpriv_flags_3505, func)
and vadapter_3504.getParentScope+() = func
and vpriv_flags_3505.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
