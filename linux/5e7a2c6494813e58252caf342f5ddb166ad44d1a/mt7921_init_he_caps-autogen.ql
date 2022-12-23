/**
 * @name linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_init_he_caps
 * @id cpp/linux/5e7a2c6494813e58252caf342f5ddb166ad44d1a/mt7921-init-he-caps
 * @description linux-5e7a2c6494813e58252caf342f5ddb166ad44d1a-mt7921_init_he_caps CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="4"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vhe_cap_elem_49) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="20"
		and target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(Literal).getValue()="16"
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="phy_cap_info"
		and target_1.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vhe_cap_elem_49
		and target_1.getParent().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0")
}

from Function func, Variable vhe_cap_elem_49
where
func_0(func)
and func_1(vhe_cap_elem_49)
and vhe_cap_elem_49.getType().hasName("ieee80211_he_cap_elem *")
and vhe_cap_elem_49.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
