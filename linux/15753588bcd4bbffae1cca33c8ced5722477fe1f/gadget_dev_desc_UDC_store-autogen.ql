/**
 * @name linux-15753588bcd4bbffae1cca33c8ced5722477fe1f-gadget_dev_desc_UDC_store
 * @id cpp/linux/15753588bcd4bbffae1cca33c8ced5722477fe1f/gadget-dev-desc-UDC-store
 * @description linux-15753588bcd4bbffae1cca33c8ced5722477fe1f-gadget_dev_desc_UDC_store 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpage_257, Parameter vlen_257, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpage_257
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_257
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-75"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="75"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

from Function func, Parameter vpage_257, Parameter vlen_257
where
not func_0(vpage_257, vlen_257, func)
and vpage_257.getType().hasName("const char *")
and vlen_257.getType().hasName("size_t")
and vpage_257.getParentScope+() = func
and vlen_257.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
