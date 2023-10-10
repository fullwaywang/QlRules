/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_rc_update
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-sta-rc-update
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_sta_rc_update CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhw_1009, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getTarget().hasName("mt7915_hw_phy")
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhw_1009
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_0)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("mt7915_phy *")
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_1)
}

predicate func_2(Parameter vhw_1009, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("ieee80211_queue_work")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vhw_1009
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rc_work"
		and target_2.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("mt7915_dev *")
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_2))
}

from Function func, Parameter vhw_1009
where
not func_0(vhw_1009, func)
and not func_1(func)
and not func_2(vhw_1009, func)
and vhw_1009.getType().hasName("ieee80211_hw *")
and vhw_1009.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
