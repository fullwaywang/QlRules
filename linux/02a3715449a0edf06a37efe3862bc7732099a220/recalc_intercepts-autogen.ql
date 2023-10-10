/**
 * @name linux-02a3715449a0edf06a37efe3862bc7732099a220-recalc_intercepts
 * @id cpp/linux/02a3715449a0edf06a37efe3862bc7732099a220/recalc-intercepts
 * @description linux-02a3715449a0edf06a37efe3862bc7732099a220-recalc_intercepts CVE-2021-3656
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vc_124, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("vmcb_set_intercept")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_124
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0))
}

predicate func_1(Variable vc_124, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("vmcb_set_intercept")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_124
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Variable vc_124) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("vmcb_clr_intercept")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vc_124)
}

from Function func, Variable vc_124
where
not func_0(vc_124, func)
and not func_1(vc_124, func)
and vc_124.getType().hasName("vmcb_control_area *")
and func_2(vc_124)
and vc_124.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
