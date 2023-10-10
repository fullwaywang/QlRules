/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_mcu_beacon_check_caps
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-mcu-beacon-check-caps
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_mcu_beacon_check_caps CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(BitwiseAndExpr target_0 |
		target_0.getLeftOperand() instanceof PointerFieldAccess
		and target_0.getRightOperand() instanceof Literal
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vbc_2429, Variable vht_2426) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="cap_info"
		and target_1.getQualifier().(VariableAccess).getTarget()=vht_2426
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbc_2429)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="1"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vbc_2429) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vbc_2429
		and target_3.getRValue() instanceof PointerFieldAccess)
}

predicate func_4(Variable vie_2428, Variable vbc_2429, Variable vvc_2423, Variable vht_2426) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ldpc"
		and target_4.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvc_2423
		and target_4.getExpr().(AssignOrExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vbc_2429
		and target_4.getExpr().(AssignOrExpr).getRValue().(NotExpr).getOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand() instanceof Literal
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vie_2428
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vie_2428
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vht_2426)
}

from Function func, Variable vie_2428, Variable vbc_2429, Variable vvc_2423, Variable vht_2426
where
not func_0(func)
and func_1(vbc_2429, vht_2426)
and func_2(func)
and func_3(vbc_2429)
and func_4(vie_2428, vbc_2429, vvc_2423, vht_2426)
and vie_2428.getType().hasName("const u8 *")
and vbc_2429.getType().hasName("u32")
and vvc_2423.getType().hasName("mt7915_vif_cap *")
and vht_2426.getType().hasName("const ieee80211_ht_cap *")
and vie_2428.getParentScope+() = func
and vbc_2429.getParentScope+() = func
and vvc_2423.getParentScope+() = func
and vht_2426.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
