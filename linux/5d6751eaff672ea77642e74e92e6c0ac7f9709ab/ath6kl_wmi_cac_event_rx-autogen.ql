/**
 * @name linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_cac_event_rx
 * @id cpp/linux/5d6751eaff672ea77642e74e92e6c0ac7f9709ab/ath6kl_wmi_cac_event_rx
 * @description linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_cac_event_rx 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vreply_1509, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="ac"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreply_1509
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ath6kl_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid AC: %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="ac"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreply_1509
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vdatap_1506, Variable vreply_1509) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vreply_1509
		and target_3.getRValue().(VariableAccess).getTarget()=vdatap_1506)
}

from Function func, Parameter vdatap_1506, Variable vreply_1509
where
not func_0(vreply_1509, func)
and vreply_1509.getType().hasName("wmi_cac_event *")
and func_3(vdatap_1506, vreply_1509)
and vdatap_1506.getParentScope+() = func
and vreply_1509.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
