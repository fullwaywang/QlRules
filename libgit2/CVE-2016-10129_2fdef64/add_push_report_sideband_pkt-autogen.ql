/**
 * @name libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-add_push_report_sideband_pkt
 * @id cpp/libgit2/2fdef641fd0dd2828bd948234ae86de75221a11a/add-push-report-sideband-pkt
 * @description libgit2-2fdef641fd0dd2828bd948234ae86de75221a11a-src/transports/smart_protocol.c-add_push_report_sideband_pkt CVE-2016-10129
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, LabelStmt target_0) {
		target_0.toString() = "label ...:"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vpkt_730, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpkt_730
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(ContinueStmt).toString() = "continue;"
}

predicate func_2(Function func, LabelStmt target_2) {
		target_2.toString() = "label ...:"
		and target_2.getName() ="done"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vpkt_730, LabelStmt target_0, IfStmt target_1, LabelStmt target_2
where
func_0(func, target_0)
and func_1(vpkt_730, target_1)
and func_2(func, target_2)
and vpkt_730.getType().hasName("git_pkt *")
and vpkt_730.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
