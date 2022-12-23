/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_hwrate_to_tx_rate
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-hwrate-to-tx-rate
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_hwrate_to_tx_rate CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_26(Parameter vrate_n_flags_1287, Parameter vband_1288) {
	exists(FunctionCall target_26 |
		target_26.getTarget().hasName("iwl_mvm_legacy_rate_to_mac80211_idx")
		and not target_26.getTarget().hasName("iwl_mvm_legacy_hw_idx_to_mac80211_idx")
		and target_26.getArgument(0).(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_26.getArgument(1).(VariableAccess).getTarget()=vband_1288)
}

predicate func_27(Parameter vrate_n_flags_1287, Function func) {
	exists(DeclStmt target_27 |
		target_27.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_27.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="7"
		and target_27.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_27)
}

predicate func_28(Parameter vrate_n_flags_1287, Function func) {
	exists(DeclStmt target_28 |
		target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getThen().(BitwiseOrExpr).getRightOperand().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="7"
		and target_28.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ConditionalExpr).getElse() instanceof BitwiseAndExpr
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_28)
}

predicate func_29(Parameter vrate_n_flags_1287) {
	exists(FunctionCall target_29 |
		target_29.getTarget().hasName("iwl_mvm_get_hwrate_chan_width")
		and target_29.getArgument(0).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_29.getArgument(0).(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="14336"
		and target_29.getArgument(0).(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="7"
		and target_29.getArgument(0).(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="11")
}

predicate func_30(Parameter vr_1289) {
	exists(EqualityOperation target_30 |
		target_30.getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_30.getAnOperand().(BinaryBitwiseOperation).getValue()="512"
		and target_30.getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_30.getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignOrExpr).getLValue() instanceof PointerFieldAccess
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="idx"
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1289
		and target_30.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("u32"))
}

predicate func_32(Parameter vrate_n_flags_1287, Parameter vr_1289) {
	exists(EqualityOperation target_32 |
		target_32.getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_32.getAnOperand().(BinaryBitwiseOperation).getValue()="768"
		and target_32.getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="3"
		and target_32.getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ieee80211_rate_set_vht")
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_1289
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("u32")
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_32.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignOrExpr).getLValue() instanceof PointerFieldAccess)
}

predicate func_34(Parameter vr_1289) {
	exists(EqualityOperation target_34 |
		target_34.getAnOperand().(VariableAccess).getType().hasName("u32")
		and target_34.getAnOperand().(BinaryBitwiseOperation).getValue()="1024"
		and target_34.getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="4"
		and target_34.getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="idx"
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr_1289
		and target_34.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_37(Parameter vr_1289) {
	exists(PointerFieldAccess target_37 |
		target_37.getTarget().getName()="flags"
		and target_37.getQualifier().(VariableAccess).getTarget()=vr_1289)
}

predicate func_41(Parameter vrate_n_flags_1287, Parameter vr_1289) {
	exists(BitwiseAndExpr target_41 |
		target_41.getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_41.getRightOperand().(Literal).getValue()="15"
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ieee80211_rate_set_vht")
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vr_1289
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_41.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1")
}

predicate func_42(Parameter vrate_n_flags_1287, Function func) {
	exists(SwitchStmt target_42 |
		target_42.getExpr().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vrate_n_flags_1287
		and target_42.getExpr().(BitwiseAndExpr).getRightOperand() instanceof BinaryBitwiseOperation
		and target_42.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr() instanceof BinaryBitwiseOperation
		and target_42.getStmt().(BlockStmt).getStmt(1).(BreakStmt).toString() = "break;"
		and target_42.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr() instanceof BinaryBitwiseOperation
		and target_42.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getLValue() instanceof PointerFieldAccess
		and target_42.getStmt().(BlockStmt).getStmt(4).(BreakStmt).toString() = "break;"
		and target_42.getStmt().(BlockStmt).getStmt(5).(SwitchCase).getExpr() instanceof BinaryBitwiseOperation
		and target_42.getStmt().(BlockStmt).getStmt(6).(ExprStmt).getExpr().(AssignOrExpr).getLValue() instanceof PointerFieldAccess
		and target_42.getStmt().(BlockStmt).getStmt(7).(BreakStmt).toString() = "break;"
		and target_42.getStmt().(BlockStmt).getStmt(8).(SwitchCase).getExpr() instanceof BinaryBitwiseOperation
		and target_42.getStmt().(BlockStmt).getStmt(9).(ExprStmt).getExpr().(AssignOrExpr).getLValue() instanceof PointerFieldAccess
		and target_42.getStmt().(BlockStmt).getStmt(10).(BreakStmt).toString() = "break;"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_42)
}

predicate func_54(Function func) {
	exists(LabelStmt target_54 |
		target_54.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_54)
}

from Function func, Parameter vrate_n_flags_1287, Parameter vband_1288, Parameter vr_1289
where
func_26(vrate_n_flags_1287, vband_1288)
and not func_27(vrate_n_flags_1287, func)
and not func_28(vrate_n_flags_1287, func)
and not func_29(vrate_n_flags_1287)
and not func_30(vr_1289)
and not func_32(vrate_n_flags_1287, vr_1289)
and not func_34(vr_1289)
and func_37(vr_1289)
and func_41(vrate_n_flags_1287, vr_1289)
and func_42(vrate_n_flags_1287, func)
and func_54(func)
and vrate_n_flags_1287.getType().hasName("u32")
and vband_1288.getType().hasName("nl80211_band")
and vr_1289.getType().hasName("ieee80211_tx_rate *")
and vrate_n_flags_1287.getParentScope+() = func
and vband_1288.getParentScope+() = func
and vr_1289.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
