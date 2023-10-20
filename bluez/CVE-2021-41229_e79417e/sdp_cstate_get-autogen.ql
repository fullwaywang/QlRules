/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-sdp_cstate_get
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/sdp-cstate-get
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-request.c-sdp_cstate_get CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_2, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sdp_cstate_cleanup")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sock"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_req_t *")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vcstate_278, PointerDereferenceExpr target_3, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getType().hasName("sdp_cont_info_t **")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("sdp_get_cont_info")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sdp_req_t *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcstate_278
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1)
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vcstate_278, PointerDereferenceExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vcstate_278
}

from Function func, Parameter vcstate_278, EqualityOperation target_2, PointerDereferenceExpr target_3
where
not func_0(target_2, func)
and not func_1(vcstate_278, target_3, func)
and func_2(target_2)
and func_3(vcstate_278, target_3)
and vcstate_278.getType().hasName("sdp_cont_state_t **")
and vcstate_278.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
