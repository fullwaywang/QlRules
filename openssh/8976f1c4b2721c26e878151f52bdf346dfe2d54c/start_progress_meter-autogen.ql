/**
 * @name openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-start_progress_meter
 * @id cpp/openssh/8976f1c4b2721c26e878151f52bdf346dfe2d54c/start-progress-meter
 * @description openssh-8976f1c4b2721c26e878151f52bdf346dfe2d54c-progressmeter.c-start_progress_meter CVE-2019-6109
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(FunctionCall target_3, Function func, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("refresh_progress_meter")
		and target_1.getParent().(IfStmt).getCondition()=target_3
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, IfStmt target_2) {
		target_2.getCondition().(FunctionCall).getTarget().hasName("can_output")
		and target_2.getThen() instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(FunctionCall target_3) {
		target_3.getTarget().hasName("can_output")
}

from Function func, ExprStmt target_1, IfStmt target_2, FunctionCall target_3
where
func_1(target_3, func, target_1)
and func_2(func, target_2)
and func_3(target_3)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
