/**
 * @name linux-66e3531b33ee51dad17c463b4d9c9f52e341503d-xennet_poll
 * @id cpp/linux/66e3531b33ee51dad17c463b4d9c9f52e341503d/xennet_poll
 * @description linux-66e3531b33ee51dad17c463b4d9c9f52e341503d-xennet_poll CVE-2022-23042
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vqueue_1215, Variable verr_1226) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="broken"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="info"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1215
		and target_0.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=verr_1226
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0")
}

predicate func_3(Variable vqueue_1215, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("spin_unlock")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="rx_lock"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vqueue_1215
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Variable vqueue_1215, Variable vrinfo_1218, Variable vrp_1221, Variable vtmpq_1225, Variable vneed_xdp_flush_1227) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("xennet_get_responses")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vqueue_1215
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vrinfo_1218
		and target_4.getArgument(2).(VariableAccess).getTarget()=vrp_1221
		and target_4.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vtmpq_1225
		and target_4.getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vneed_xdp_flush_1227)
}

predicate func_5(Variable vqueue_1215) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="rx"
		and target_5.getQualifier().(VariableAccess).getTarget()=vqueue_1215)
}

from Function func, Variable vqueue_1215, Variable vrinfo_1218, Variable vrp_1221, Variable vtmpq_1225, Variable verr_1226, Variable vneed_xdp_flush_1227
where
not func_0(vqueue_1215, verr_1226)
and func_3(vqueue_1215, func)
and vqueue_1215.getType().hasName("netfront_queue *")
and func_4(vqueue_1215, vrinfo_1218, vrp_1221, vtmpq_1225, vneed_xdp_flush_1227)
and func_5(vqueue_1215)
and vrinfo_1218.getType().hasName("netfront_rx_info")
and vrp_1221.getType().hasName("RING_IDX")
and vtmpq_1225.getType().hasName("sk_buff_head")
and verr_1226.getType().hasName("int")
and vneed_xdp_flush_1227.getType().hasName("bool")
and vqueue_1215.getParentScope+() = func
and vrinfo_1218.getParentScope+() = func
and vrp_1221.getParentScope+() = func
and vtmpq_1225.getParentScope+() = func
and verr_1226.getParentScope+() = func
and vneed_xdp_flush_1227.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
