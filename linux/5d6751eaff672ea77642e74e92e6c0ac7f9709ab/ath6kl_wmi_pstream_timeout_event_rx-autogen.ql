/**
 * @name linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_pstream_timeout_event_rx
 * @id cpp/linux/5d6751eaff672ea77642e74e92e6c0ac7f9709ab/ath6kl_wmi_pstream_timeout_event_rx
 * @description linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_pstream_timeout_event_rx 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vev_1173, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="traffic_class"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_1173
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ath6kl_err")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid traffic class: %d\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="traffic_class"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_1173
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_3(Parameter vdatap_1170, Variable vev_1173) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vev_1173
		and target_3.getRValue().(VariableAccess).getTarget()=vdatap_1170)
}

from Function func, Parameter vdatap_1170, Variable vev_1173
where
not func_0(vev_1173, func)
and vev_1173.getType().hasName("wmi_pstream_timeout_event *")
and func_3(vdatap_1170, vev_1173)
and vdatap_1170.getParentScope+() = func
and vev_1173.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
