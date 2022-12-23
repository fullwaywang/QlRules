/**
 * @name linux-b43d1f9f7067c6759b1051e8ecb84e82cef569fe-prb_calc_retire_blk_tmo
 * @id cpp/linux/b43d1f9f7067c6759b1051e8ecb84e82cef569fe/prb-calc-retire-blk-tmo
 * @description linux-b43d1f9f7067c6759b1051e8ecb84e82cef569fe-prb_calc_retire_blk_tmo 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable verr_525) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(Literal).getValue()="8"
		and target_0.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=verr_525)
}

from Function func, Variable verr_525
where
not func_0(verr_525)
and verr_525.getType().hasName("int")
and verr_525.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
