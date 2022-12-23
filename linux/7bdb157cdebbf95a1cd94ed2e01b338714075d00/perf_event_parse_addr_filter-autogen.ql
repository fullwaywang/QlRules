/**
 * @name linux-7bdb157cdebbf95a1cd94ed2e01b338714075d00-perf_event_parse_addr_filter
 * @id cpp/linux/7bdb157cdebbf95a1cd94ed2e01b338714075d00/perf_event_parse_addr_filter
 * @description linux-7bdb157cdebbf95a1cd94ed2e01b338714075d00-perf_event_parse_addr_filter 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vfilename_10023, Variable vkernel_10026) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("kfree")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfilename_10023
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vkernel_10026)
}

predicate func_2(Variable vfilename_10023) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getTarget()=vfilename_10023
		and target_2.getRValue().(Literal).getValue()="0")
}

predicate func_3(Function func) {
	exists(LabelStmt target_3 |
		target_3.toString() = "label ...:"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vfilename_10023) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("kfree")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vfilename_10023)
}

from Function func, Variable vfilename_10023, Variable vkernel_10026
where
func_1(vfilename_10023, vkernel_10026)
and func_2(vfilename_10023)
and func_3(func)
and vfilename_10023.getType().hasName("char *")
and func_4(vfilename_10023)
and vkernel_10026.getType().hasName("unsigned int")
and vfilename_10023.getParentScope+() = func
and vkernel_10026.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
