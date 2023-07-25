/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-sdp_cstate_rsp
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/sdp-cstate-rsp
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-request.c-sdp_cstate_rsp CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Parameter vcstate_622, ReturnStmt target_7, ExprStmt target_11) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_622
		and target_1.getLesserOperand().(ValueFieldAccess).getTarget().getName()="data_size"
		and target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_1.getParent().(IfStmt).getThen()=target_7
		and target_1.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(EqualityOperation target_6, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("sdp_cont_info_free")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(EqualityOperation target_6, Function func) {
	exists(ReturnStmt target_3 |
		target_3.getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Variable vcache_626, ExprStmt target_11, PointerArithmeticOperation target_12, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcache_626
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="buf"
		and target_4.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_4)
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Function func) {
	exists(IfStmt target_5 |
		target_5.getCondition() instanceof EqualityOperation
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sdp_cont_info_free")
		and target_5.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_5.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_5))
}

predicate func_6(Variable vcache_626, Parameter vcstate_622, ReturnStmt target_7, EqualityOperation target_6) {
		target_6.getAnOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_6.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_622
		and target_6.getAnOperand().(PointerFieldAccess).getTarget().getName()="data_size"
		and target_6.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_626
		and target_6.getParent().(IfStmt).getThen()=target_7
}

predicate func_7(Parameter vbuf_622, EqualityOperation target_6, ReturnStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("sdp_set_cstate_pdu")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_622
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_7.getParent().(IfStmt).getCondition()=target_6
}

predicate func_8(Parameter vcstate_622, VariableAccess target_8) {
		target_8.getTarget()=vcstate_622
		and target_8.getParent().(FunctionCall).getParent().(Initializer).getExpr() instanceof FunctionCall
}

predicate func_9(Parameter vcstate_622, Initializer target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("sdp_get_cached_rsp")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcstate_622
}

predicate func_10(Variable vcache_626, ReturnStmt target_13, ExprStmt target_11, VariableAccess target_10) {
		target_10.getTarget()=vcache_626
		and target_10.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_13
		and target_10.getLocation().isBefore(target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_11(Variable vcache_626, Parameter vcstate_622, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_size"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_626
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="data_size"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_626
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_11.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_622
}

predicate func_12(Variable vcache_626, Parameter vcstate_622, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_12.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcache_626
		and target_12.getAnOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_12.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_622
}

predicate func_13(ReturnStmt target_13) {
		target_13.getExpr().(Literal).getValue()="0"
}

from Function func, Variable vcache_626, Parameter vcstate_622, Parameter vbuf_622, EqualityOperation target_6, ReturnStmt target_7, VariableAccess target_8, Initializer target_9, VariableAccess target_10, ExprStmt target_11, PointerArithmeticOperation target_12, ReturnStmt target_13
where
not func_1(vcstate_622, target_7, target_11)
and not func_2(target_6, func)
and not func_3(target_6, func)
and not func_4(vcache_626, target_11, target_12, func)
and not func_5(func)
and func_6(vcache_626, vcstate_622, target_7, target_6)
and func_7(vbuf_622, target_6, target_7)
and func_8(vcstate_622, target_8)
and func_9(vcstate_622, target_9)
and func_10(vcache_626, target_13, target_11, target_10)
and func_11(vcache_626, vcstate_622, target_11)
and func_12(vcache_626, vcstate_622, target_12)
and func_13(target_13)
and vcache_626.getType().hasName("sdp_buf_t *")
and vcstate_622.getType().hasName("sdp_cont_state_t *")
and vbuf_622.getType().hasName("sdp_buf_t *")
and vcache_626.getParentScope+() = func
and vcstate_622.getParentScope+() = func
and vbuf_622.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
