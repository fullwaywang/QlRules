/**
 * @name linux-353c0956a618a07ba4bbe7ad00ff29fe70e8412a-kvm_read_guest_virt
 * @id cpp/linux/353c0956a618a07ba4bbe7ad00ff29fe70e8412a/kvm_read_guest_virt
 * @description linux-353c0956a618a07ba4bbe7ad00ff29fe70e8412a-kvm_read_guest_virt CVE-2019-7222
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_5115, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("__memset")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_5115
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getValue()="24"
		and target_0.getExpr().(FunctionCall).getArgument(2).(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vexception_5115
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

from Function func, Parameter vexception_5115
where
not func_0(vexception_5115, func)
and vexception_5115.getType().hasName("x86_exception *")
and vexception_5115.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
