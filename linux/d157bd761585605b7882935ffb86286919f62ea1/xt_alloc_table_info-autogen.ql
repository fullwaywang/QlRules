/**
 * @name linux-d157bd761585605b7882935ffb86286919f62ea1-xt_alloc_table_info
 * @id cpp/linux/d157bd761585605b7882935ffb86286919f62ea1/xt_alloc_table_info
 * @description linux-d157bd761585605b7882935ffb86286919f62ea1-xt_alloc_table_info 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vinfo_659, Variable vsz_660, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsz_660
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="64"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vinfo_659
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Variable vinfo_659) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vinfo_659)
}

from Function func, Variable vinfo_659, Variable vsz_660
where
not func_0(vinfo_659, vsz_660, func)
and vinfo_659.getType().hasName("xt_table_info *")
and func_1(vinfo_659)
and vsz_660.getType().hasName("size_t")
and vinfo_659.getParentScope+() = func
and vsz_660.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
