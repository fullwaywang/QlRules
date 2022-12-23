/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_rx_chub_update_mcc
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-mvm-rx-chub-update-mcc
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_mvm_rx_chub_update_mcc CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vwgds_tbl_idx_561) {
	exists(Literal target_0 |
		target_0.getValue()="0"
		and not target_0.getValue()="1"
		and target_0.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vwgds_tbl_idx_561)
}

predicate func_1(Function func) {
	exists(StringLiteral target_1 |
		target_1.getValue()="SAR WGDS is disabled (%d)\n"
		and not target_1.getValue()="SAR WGDS is disabled or error received (%d)\n"
		and target_1.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(SubExpr target_3 |
		target_3.getValue()="25"
		and target_3.getLeftOperand().(SizeofExprOperator).getValue()="27"
		and target_3.getLeftOperand().(SizeofExprOperator).getExprOperand().(StringLiteral).getValue()="SAR WGDS is disabled (%d)\n"
		and target_3.getRightOperand().(Literal).getValue()="2"
		and target_3.getParent().(ArrayExpr).getArrayBase().(StringLiteral).getValue()="SAR WGDS is disabled (%d)\n"
		and target_3.getEnclosingFunction() = func)
}

predicate func_5(Function func) {
	exists(StringLiteral target_5 |
		target_5.getValue()="SAR WGDS is disabled or error received (%d)\n"
		and target_5.getEnclosingFunction() = func)
}

from Function func, Variable vwgds_tbl_idx_561
where
func_0(vwgds_tbl_idx_561)
and func_1(func)
and func_3(func)
and not func_5(func)
and vwgds_tbl_idx_561.getType().hasName("int")
and vwgds_tbl_idx_561.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
