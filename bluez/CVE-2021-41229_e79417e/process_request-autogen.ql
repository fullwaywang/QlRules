/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-process_request
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/process-request
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-request.c-process_request CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vreqhdr_961, Parameter vreq_959, EqualityOperation target_2, SwitchStmt target_3, ExprStmt target_4, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="opcode"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_959
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="pdu_id"
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreqhdr_961
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vreq_959, VariableAccess target_5, ExprStmt target_6, RelationalOperation target_7) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("sdp_cstate_cleanup")
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sock"
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_959
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vreqhdr_961, Parameter vreq_959, EqualityOperation target_2) {
		target_2.getAnOperand().(FunctionCall).getTarget().hasName("__bswap_16")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="plen"
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreqhdr_961
		and target_2.getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="len"
		and target_2.getAnOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_959
		and target_2.getAnOperand().(SubExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getAnOperand().(SubExpr).getRightOperand().(SizeofTypeOperator).getValue()="5"
}

predicate func_3(Variable vreqhdr_961, Parameter vreq_959, SwitchStmt target_3) {
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="pdu_id"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreqhdr_961
		and target_3.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="2"
		and target_3.getStmt().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("service_search_req")
		and target_3.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreq_959
		and target_3.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pdu_id"
		and target_3.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="3"
}

predicate func_4(Parameter vreq_959, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("service_search_req")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreq_959
}

predicate func_5(Variable vstatus_965, VariableAccess target_5) {
		target_5.getTarget()=vstatus_965
}

predicate func_6(Variable vstatus_965, Parameter vreq_959, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_965
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("service_remove_req")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vreq_959
}

predicate func_7(Parameter vreq_959, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(FunctionCall).getTarget().hasName("send")
		and target_7.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="sock"
		and target_7.getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_959
		and target_7.getLesserOperand().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="data"
		and target_7.getLesserOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="data_size"
		and target_7.getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_7.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vreqhdr_961, Variable vstatus_965, Parameter vreq_959, EqualityOperation target_2, SwitchStmt target_3, ExprStmt target_4, VariableAccess target_5, ExprStmt target_6, RelationalOperation target_7
where
not func_0(vreqhdr_961, vreq_959, target_2, target_3, target_4, func)
and not func_1(vreq_959, target_5, target_6, target_7)
and func_2(vreqhdr_961, vreq_959, target_2)
and func_3(vreqhdr_961, vreq_959, target_3)
and func_4(vreq_959, target_4)
and func_5(vstatus_965, target_5)
and func_6(vstatus_965, vreq_959, target_6)
and func_7(vreq_959, target_7)
and vreqhdr_961.getType().hasName("sdp_pdu_hdr_t *")
and vstatus_965.getType().hasName("int")
and vreq_959.getType().hasName("sdp_req_t *")
and vreqhdr_961.getParentScope+() = func
and vstatus_965.getParentScope+() = func
and vreq_959.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
