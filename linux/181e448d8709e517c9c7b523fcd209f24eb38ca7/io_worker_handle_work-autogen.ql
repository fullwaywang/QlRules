/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_worker_handle_work
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-worker-handle-work
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_worker_handle_work 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vworker_393, Variable vwq_398) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vworker_393
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vworker_393
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("override_creds")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="creds"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwq_398)
}

predicate func_1(Parameter vworker_393) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="mm"
		and target_1.getQualifier().(VariableAccess).getTarget()=vworker_393)
}

predicate func_2(Variable vwq_398) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="mm"
		and target_2.getQualifier().(VariableAccess).getTarget()=vwq_398)
}

from Function func, Parameter vworker_393, Variable vwq_398
where
not func_0(vworker_393, vwq_398)
and vworker_393.getType().hasName("io_worker *")
and func_1(vworker_393)
and vwq_398.getType().hasName("io_wq *")
and func_2(vwq_398)
and vworker_393.getParentScope+() = func
and vwq_398.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
