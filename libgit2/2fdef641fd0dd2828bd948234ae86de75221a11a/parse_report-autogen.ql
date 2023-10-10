/**
 * @name libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-parse_report
 * @id cpp/libgit2/2fdef641fd0dd2828bd948234ae86de75221a11a/parse-report
 * @description libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-src/transports/smart_protocol.c-parse_report CVE-2016-10129
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpkt_792, IfStmt target_0) {
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpkt_792
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
}

from Function func, Variable vpkt_792, IfStmt target_0
where
func_0(vpkt_792, target_0)
and vpkt_792.getType().hasName("git_pkt *")
and vpkt_792.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
