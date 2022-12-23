/**
 * @name linux-cc25b994acfbc901429da682d0f73c190e960206-x509_decode_time
 * @id cpp/linux/cc25b994acfbc901429da682d0f73c190e960206/x509-decode-time
 * @description linux-cc25b994acfbc901429da682d0f73c190e960206-x509_decode_time CVE-2015-5327
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmonth_lengths_497, Variable vmon_500) {
	exists(SubExpr target_0 |
		target_0.getLeftOperand().(VariableAccess).getTarget()=vmon_500
		and target_0.getRightOperand().(Literal).getValue()="1"
		and target_0.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmonth_lengths_497)
}

predicate func_1(Variable vday_500, Variable vhour_500, Variable vmin_500, Variable vsec_500, Variable vmon_len_500, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vday_500
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmon_len_500
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vhour_500
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="23"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmin_500
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="59"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsec_500
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="59"
		and target_1.getThen().(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Variable vyear_500, Variable vmon_500) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vyear_500
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1970"
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmon_500
		and target_2.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmon_500
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="12")
}

predicate func_3(Variable vday_500) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vday_500
		and target_3.getGreaterOperand().(Literal).getValue()="1")
}

predicate func_5(Function func) {
	exists(LogicalOrExpr target_5 |
		target_5.getAnOperand() instanceof LogicalOrExpr
		and target_5.getAnOperand() instanceof RelationalOperation
		and target_5.getEnclosingFunction() = func)
}

from Function func, Variable vmonth_lengths_497, Variable vyear_500, Variable vmon_500, Variable vday_500, Variable vhour_500, Variable vmin_500, Variable vsec_500, Variable vmon_len_500
where
not func_0(vmonth_lengths_497, vmon_500)
and not func_1(vday_500, vhour_500, vmin_500, vsec_500, vmon_len_500, func)
and func_2(vyear_500, vmon_500)
and func_3(vday_500)
and func_5(func)
and vmonth_lengths_497.getType().hasName("const unsigned char[]")
and vyear_500.getType().hasName("unsigned int")
and vmon_500.getType().hasName("unsigned int")
and vday_500.getType().hasName("unsigned int")
and vhour_500.getType().hasName("unsigned int")
and vmin_500.getType().hasName("unsigned int")
and vsec_500.getType().hasName("unsigned int")
and vmon_len_500.getType().hasName("unsigned int")
and vmonth_lengths_497.getParentScope+() = func
and vyear_500.getParentScope+() = func
and vmon_500.getParentScope+() = func
and vday_500.getParentScope+() = func
and vhour_500.getParentScope+() = func
and vmin_500.getParentScope+() = func
and vsec_500.getParentScope+() = func
and vmon_len_500.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
