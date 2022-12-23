/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_rc_work
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-sta-rc-work
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_rc_work CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmsta_995, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="hw"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mt76"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="phy"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vif"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsta_995
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_1(Variable vdev_996, Variable vhw_997, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ieee80211_queue_work")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhw_997
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rc_work"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_996
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Variable vmsta_995, Variable vdev_996, Variable vhw_997
where
func_0(vmsta_995, func)
and func_1(vdev_996, vhw_997, func)
and vmsta_995.getType().hasName("mt7915_sta *")
and vdev_996.getType().hasName("mt7915_dev *")
and vhw_997.getType().hasName("ieee80211_hw *")
and vmsta_995.getParentScope+() = func
and vdev_996.getParentScope+() = func
and vhw_997.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
