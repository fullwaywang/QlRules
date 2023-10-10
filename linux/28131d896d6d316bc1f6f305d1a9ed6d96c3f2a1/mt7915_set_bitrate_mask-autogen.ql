/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_set_bitrate_mask
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-set-bitrate-mask
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_set_bitrate_mask CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Initializer target_0 |
		target_0.getExpr().(PointerFieldAccess).getTarget().getName()="band"
		and target_0.getExpr().(PointerFieldAccess).getQualifier() instanceof ValueFieldAccess
		and target_0.getExpr().getEnclosingFunction() = func)
}

predicate func_1(Parameter vhw_1018) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("mt7915_hw_phy")
		and target_1.getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhw_1018)
}

predicate func_3(Function func) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="dev"
		and target_3.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("mt7915_phy *")
		and target_3.getDeclaration().getParentScope+() = func)
}

predicate func_4(Function func) {
	exists(DeclStmt target_4 |
		target_4.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr() instanceof EnumConstantAccess
		and func.getEntryPoint().(BlockStmt).getStmt(3)=target_4)
}

predicate func_6(Parameter vhw_1018) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("ieee80211_queue_work")
		and target_6.getArgument(0).(VariableAccess).getTarget()=vhw_1018
		and target_6.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rc_work"
		and target_6.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("mt7915_dev *"))
}

predicate func_8(Function func) {
	exists(VariableDeclarationEntry target_8 |
		target_8.getVariable().getInitializer() instanceof Initializer
		and target_8.getDeclaration().getParentScope+() = func)
}

predicate func_9(Variable vmvif_1021) {
	exists(ValueFieldAccess target_9 |
		target_9.getTarget().getName()="chan"
		and target_9.getQualifier().(PointerFieldAccess).getTarget().getName()="chandef"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mt76"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phy"
		and target_9.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvif_1021)
}

predicate func_10(Parameter vmask_1019, Variable vband_1022, Function func) {
	exists(IfStmt target_10 |
		target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="gi"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="control"
		and target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmask_1019
		and target_10.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vband_1022
		and target_10.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_10.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10)
}

predicate func_11(Variable vchanged_1023) {
	exists(AssignExpr target_11 |
		target_11.getLValue().(VariableAccess).getTarget()=vchanged_1023
		and target_11.getRValue() instanceof EnumConstantAccess)
}

from Function func, Parameter vhw_1018, Parameter vmask_1019, Variable vmvif_1021, Variable vband_1022, Variable vchanged_1023
where
func_0(func)
and not func_1(vhw_1018)
and not func_3(func)
and not func_4(func)
and not func_6(vhw_1018)
and func_8(func)
and func_9(vmvif_1021)
and func_10(vmask_1019, vband_1022, func)
and func_11(vchanged_1023)
and vhw_1018.getType().hasName("ieee80211_hw *")
and vmask_1019.getType().hasName("const cfg80211_bitrate_mask *")
and vmvif_1021.getType().hasName("mt7915_vif *")
and vchanged_1023.getType().hasName("u32")
and vhw_1018.getParentScope+() = func
and vmask_1019.getParentScope+() = func
and vmvif_1021.getParentScope+() = func
and vband_1022.getParentScope+() = func
and vchanged_1023.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
