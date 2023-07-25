/**
 * @name curl-5019c780958c3a8dbe64123aa90e6eaff1b84cfa-hostmatch
 * @id cpp/curl/5019c780958c3a8dbe64123aa90e6eaff1b84cfa/hostmatch
 * @description curl-5019c780958c3a8dbe64123aa90e6eaff1b84cfa-lib/hostcheck.c-hostmatch CVE-2014-0139
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vhostname_41, ConditionalExpr target_1, ConditionalExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("inet_pton")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(Literal).getValue()="2"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhostname_41
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("in_addr")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_2.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vhostname_41, ConditionalExpr target_1) {
		target_1.getCondition().(FunctionCall).getTarget().hasName("Curl_raw_equal")
		and target_1.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhostname_41
		and target_1.getThen().(Literal).getValue()="1"
		and target_1.getElse().(Literal).getValue()="0"
}

predicate func_2(Parameter vhostname_41, ConditionalExpr target_2) {
		target_2.getCondition().(FunctionCall).getTarget().hasName("Curl_raw_equal")
		and target_2.getCondition().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vhostname_41
		and target_2.getThen().(Literal).getValue()="1"
		and target_2.getElse().(Literal).getValue()="0"
}

from Function func, Parameter vhostname_41, ConditionalExpr target_1, ConditionalExpr target_2
where
not func_0(vhostname_41, target_1, target_2, func)
and func_1(vhostname_41, target_1)
and func_2(vhostname_41, target_2)
and vhostname_41.getType().hasName("const char *")
and vhostname_41.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
