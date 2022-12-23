/**
 * @name linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-consume_one_event
 * @id cpp/linux/e99502f76271d6bc4e374fe368c50c67a1fd3070/consume-one-event
 * @description linux-e99502f76271d6bc4e374fe368c50c67a1fd3070-consume_one_event 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(NotExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("evtchn_loop_ctrl *")
		and target_0.getEnclosingFunction() = func)
}

predicate func_2(Parameter vdrop_290) {
	exists(VariableAccess target_2 |
		target_2.getTarget()=vdrop_290)
}

from Function func, Parameter vdrop_290
where
not func_0(func)
and func_2(vdrop_290)
and vdrop_290.getType().hasName("bool")
and vdrop_290.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
