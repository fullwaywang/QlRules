/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-sftpio
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/sftpio
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-sftp-client.c-sftpio CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("refresh_progress_meter")
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0))
}

predicate func_1(Variable vbwlimit_103, ExprStmt target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vbwlimit_103
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_1)
		and target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Variable vbwlimit_103, Parameter vamount_101, Function func, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("bandwidth_limit")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbwlimit_103
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vamount_101
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

from Function func, Variable vbwlimit_103, Parameter vamount_101, ExprStmt target_2
where
not func_0(func)
and not func_1(vbwlimit_103, target_2, func)
and func_2(vbwlimit_103, vamount_101, func, target_2)
and vbwlimit_103.getType().hasName("bwlimit *")
and vamount_101.getType().hasName("size_t")
and vbwlimit_103.getParentScope+() = func
and vamount_101.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
