/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-send_msg
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/send-msg
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-sftp-client.c-send_msg CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vconn_110) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition() instanceof RelationalOperation
		and target_0.getThen() instanceof AddressOfExpr
		and target_0.getElse() instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("atomiciov6")
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fd_out"
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_110
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof ConditionalExpr
		and target_0.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(5) instanceof AddressOfExpr)
}

predicate func_1(Parameter vconn_110, RelationalOperation target_1) {
		 (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
		and target_1.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="limit_kbps"
		and target_1.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_110
		and target_1.getLesserOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vconn_110, AddressOfExpr target_2) {
		target_2.getOperand().(PointerFieldAccess).getTarget().getName()="bwlimit_out"
		and target_2.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_110
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("atomiciov6")
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fd_out"
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_110
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_2.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(4) instanceof ConditionalExpr
}

predicate func_5(Parameter vconn_110, ConditionalExpr target_5) {
		target_5.getCondition() instanceof RelationalOperation
		and target_5.getThen() instanceof FunctionAccess
		and target_5.getElse() instanceof Literal
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getTarget().hasName("atomiciov6")
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="fd_out"
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_110
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(3).(Literal).getValue()="2"
		and target_5.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand().(FunctionCall).getArgument(5) instanceof AddressOfExpr
}

from Function func, Parameter vconn_110, RelationalOperation target_1, AddressOfExpr target_2, ConditionalExpr target_5
where
not func_0(vconn_110)
and func_1(vconn_110, target_1)
and func_2(vconn_110, target_2)
and func_5(vconn_110, target_5)
and vconn_110.getType().hasName("sftp_conn *")
and vconn_110.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
