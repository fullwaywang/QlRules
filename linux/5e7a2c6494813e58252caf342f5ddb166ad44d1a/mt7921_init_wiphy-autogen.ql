/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_init_wiphy
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7921-init-wiphy
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_init_wiphy CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhw_73) {
	exists(Literal target_0 |
		target_0.getValue()="256"
		and not target_0.getValue()="64"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_rx_aggregation_subframes"
		and target_0.getParent().(AssignExpr).getParent().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhw_73)
}

from Function func, Parameter vhw_73
where
func_0(vhw_73)
and vhw_73.getType().hasName("ieee80211_hw *")
and vhw_73.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
