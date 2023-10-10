/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_gen2_start_fw
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-trans-pcie-gen2-start-fw
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_trans_pcie_gen2_start_fw CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vtrans_401) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("iwl_write32")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_401
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="44"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="44"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="16843009"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_401)
}

predicate func_2(Parameter vtrans_401) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("iwl_set_bit")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_401
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_2.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="128"
		and target_2.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="7"
		and target_2.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_2.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_2.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_401)
}

predicate func_3(Parameter vtrans_401) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("iwl_write_umac_prph")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_401
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="10509380"
		and target_3.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_3.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_401)
}

predicate func_4(Parameter vtrans_401) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("iwl_write_prph")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_401
		and target_4.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="10509380"
		and target_4.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_4.getParent().(IfStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_401)
}

predicate func_6(Parameter vtrans_401) {
	exists(PointerFieldAccess target_6 |
		target_6.getTarget().getName()="trans_cfg"
		and target_6.getQualifier().(VariableAccess).getTarget()=vtrans_401)
}

from Function func, Parameter vtrans_401
where
not func_1(vtrans_401)
and func_2(vtrans_401)
and func_3(vtrans_401)
and func_4(vtrans_401)
and vtrans_401.getType().hasName("iwl_trans *")
and func_6(vtrans_401)
and vtrans_401.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
