/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_rs_data_read
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-dbgfs-rs-data-read
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_dbgfs_rs_data_read CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="valid_tx_ant %s%s%s\n"
		and not target_0.getValue()="valid_tx_ant %s%s\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vmvm_377, Variable vbufsz_378, Variable vbuff_379, Variable vdesc_380) {
	exists(ConditionalExpr target_1 |
		target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("iwl_mvm_get_valid_tx_ant")
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_377
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="4"
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_1.getThen().(StringLiteral).getValue()="ANT_C"
		and target_1.getElse().(StringLiteral).getValue()=""
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getTarget().hasName("scnprintf")
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vbuff_379
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vdesc_380
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vbufsz_378
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getTarget()=vdesc_380
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("iwl_mvm_get_valid_tx_ant")
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_377
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()="ANT_A,"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()=""
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getTarget().hasName("iwl_mvm_get_valid_tx_ant")
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmvm_377
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getThen().(StringLiteral).getValue()="ANT_B,"
		and target_1.getParent().(FunctionCall).getParent().(AssignAddExpr).getRValue().(FunctionCall).getArgument(4).(ConditionalExpr).getElse().(StringLiteral).getValue()="")
}

from Function func, Variable vmvm_377, Variable vbufsz_378, Variable vbuff_379, Variable vdesc_380
where
func_0(func)
and func_1(vmvm_377, vbufsz_378, vbuff_379, vdesc_380)
and vmvm_377.getType().hasName("iwl_mvm *")
and vbufsz_378.getType().hasName("const size_t")
and vbuff_379.getType().hasName("char *")
and vdesc_380.getType().hasName("int")
and vmvm_377.getParentScope+() = func
and vbufsz_378.getParentScope+() = func
and vbuff_379.getParentScope+() = func
and vdesc_380.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
