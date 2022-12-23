/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_mac_sta_rc_work
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-mac-sta-rc-work
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_mac_sta_rc_work CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Variable vdev_2058, Variable vsta_2059, Variable vvif_2060) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("mt7915_mcu_add_rate_ctrl")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vdev_2058
		and target_4.getArgument(1).(VariableAccess).getTarget()=vvif_2060
		and target_4.getArgument(2).(VariableAccess).getTarget()=vsta_2059)
}

predicate func_5(Variable vdev_2058, Variable vsta_2059, Variable vvif_2060) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("mt7915_mcu_add_he")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vdev_2058
		and target_5.getArgument(1).(VariableAccess).getTarget()=vvif_2060
		and target_5.getArgument(2).(VariableAccess).getTarget()=vsta_2059)
}

predicate func_6(Variable vchanged_2062) {
	exists(ExprStmt target_6 |
		target_6.getExpr() instanceof FunctionCall
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vchanged_2062)
}

from Function func, Variable vdev_2058, Variable vsta_2059, Variable vvif_2060, Variable vchanged_2062
where
func_4(vdev_2058, vsta_2059, vvif_2060)
and func_5(vdev_2058, vsta_2059, vvif_2060)
and func_6(vchanged_2062)
and vdev_2058.getType().hasName("mt7915_dev *")
and vsta_2059.getType().hasName("ieee80211_sta *")
and vvif_2060.getType().hasName("ieee80211_vif *")
and vchanged_2062.getType().hasName("u32")
and vdev_2058.getParentScope+() = func
and vsta_2059.getParentScope+() = func
and vvif_2060.getParentScope+() = func
and vchanged_2062.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
