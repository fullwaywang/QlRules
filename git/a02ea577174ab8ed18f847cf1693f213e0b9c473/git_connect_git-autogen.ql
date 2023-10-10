/**
 * @name git-a02ea577174ab8ed18f847cf1693f213e0b9c473-git_connect_git
 * @id cpp/git/a02ea577174ab8ed18f847cf1693f213e0b9c473/git-connect-git
 * @description git-a02ea577174ab8ed18f847cf1693f213e0b9c473-connect.c-git_connect_git CVE-2021-40330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpath_1048, Variable vtarget_host_1059, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtarget_host_1059
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="10"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("strchr")
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1048
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(1).(CharLiteral).getValue()="10"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("die")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="newline is forbidden in git:// hosts and repo paths"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpath_1048, Variable vtarget_host_1059, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("strbuf_addf")
		and target_1.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="%s %s%chost=%s%c"
		and target_1.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vpath_1048
		and target_1.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vtarget_host_1059
		and target_1.getExpr().(FunctionCall).getArgument(6).(Literal).getValue()="0"
}

predicate func_2(Variable vtarget_host_1059, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtarget_host_1059
		and target_2.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("xstrdup")
}

from Function func, Parameter vpath_1048, Variable vtarget_host_1059, ExprStmt target_1, ExprStmt target_2
where
not func_0(vpath_1048, vtarget_host_1059, target_1, target_2, func)
and func_1(vpath_1048, vtarget_host_1059, target_1)
and func_2(vtarget_host_1059, target_2)
and vpath_1048.getType().hasName("const char *")
and vtarget_host_1059.getType().hasName("char *")
and vpath_1048.getParentScope+() = func
and vtarget_host_1059.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
