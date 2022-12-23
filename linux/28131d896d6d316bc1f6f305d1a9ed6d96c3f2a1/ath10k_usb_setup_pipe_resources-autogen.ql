/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath10k_usb_setup_pipe_resources
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/ath10k-usb-setup-pipe-resources
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-ath10k_usb_setup_pipe_resources CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vendpoint_820) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("usb_endpoint_maxp")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vendpoint_820
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ContinueStmt).toString() = "continue;")
}

predicate func_1(Variable vendpoint_820) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="bInterval"
		and target_1.getQualifier().(VariableAccess).getTarget()=vendpoint_820)
}

from Function func, Variable vendpoint_820
where
not func_0(vendpoint_820)
and vendpoint_820.getType().hasName("usb_endpoint_descriptor *")
and func_1(vendpoint_820)
and vendpoint_820.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
