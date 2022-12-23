/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_trans_pcie_stop_device
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/-iwl-trans-pcie-stop-device
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-_iwl_trans_pcie_stop_device CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vtrans_1172, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="device_family"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="trans_cfg"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtrans_1172
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("iwl_clear_bit")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_1172
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="2097152"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="21"
		and target_0.getElse() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vtrans_1172, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("iwl_clear_bit")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtrans_1172
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getValue()="36"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="36"
		and target_1.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Parameter vtrans_1172) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("iwl_write_prph")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vtrans_1172
		and target_2.getArgument(1).(AddExpr).getValue()="12296"
		and target_2.getArgument(1).(AddExpr).getAnOperand().(AddExpr).getValue()="12288"
		and target_2.getArgument(1).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="0"
		and target_2.getArgument(1).(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="12288"
		and target_2.getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="8"
		and target_2.getArgument(2).(Literal).getValue()="512")
}

from Function func, Parameter vtrans_1172
where
not func_0(vtrans_1172, func)
and func_1(vtrans_1172, func)
and vtrans_1172.getType().hasName("iwl_trans *")
and func_2(vtrans_1172)
and vtrans_1172.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
