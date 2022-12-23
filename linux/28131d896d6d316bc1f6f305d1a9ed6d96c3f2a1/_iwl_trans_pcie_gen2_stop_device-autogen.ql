/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_trans_pcie_gen2_stop_device
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/-iwl-trans-pcie-gen2-stop-device
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_trans_pcie_gen2_stop_device CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_125) {
	exists(PointerFieldAccess target_0 |
		target_0.getTarget().getName()="device_family"
		and target_0.getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_0.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_125
		and target_0.getParent().(GEExpr).getLesserOperand() instanceof EnumConstantAccess
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen() instanceof BlockStmt)
}

predicate func_2(Variable vtrans_pcie_127, Parameter vtrans_125) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("iwl_trans_pcie_fw_reset_handshake")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_125
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="fw_reset_handshake"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_pcie_127)
}

predicate func_6(Function func) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("msleep")
		and target_6.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="100"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof PointerFieldAccess
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vtrans_125) {
	exists(ExprStmt target_7 |
		target_7.getExpr().(FunctionCall).getTarget().hasName("iwl_set_bit")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_125
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_7.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_7.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="2147483648"
		and target_7.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_7.getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="31"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof PointerFieldAccess)
}

predicate func_8(Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof PointerFieldAccess
		and target_8.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_8.getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand() instanceof PointerFieldAccess
		and target_8.getEnclosingFunction() = func)
}

predicate func_9(Parameter vtrans_125, Function func) {
	exists(IfStmt target_9 |
		target_9.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_125
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_clear_bit")
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_125
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="2097152"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="21"
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_clear_bit")
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_125
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_9.getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9)
}

predicate func_10(Parameter vtrans_125, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_125
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_set_bit")
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_125
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_10.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="31"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

from Function func, Variable vtrans_pcie_127, Parameter vtrans_125
where
func_0(vtrans_125)
and func_2(vtrans_pcie_127, vtrans_125)
and func_6(func)
and func_7(vtrans_125)
and func_8(func)
and func_9(vtrans_125, func)
and func_10(vtrans_125, func)
and vtrans_pcie_127.getType().hasName("iwl_trans_pcie *")
and vtrans_125.getType().hasName("iwl_trans *")
and vtrans_pcie_127.getParentScope+() = func
and vtrans_125.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
