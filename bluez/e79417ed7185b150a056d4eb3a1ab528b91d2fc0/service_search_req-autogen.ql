/**
 * @name bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-service_search_req
 * @id cpp/bluez/e79417ed7185b150a056d4eb3a1ab528b91d2fc0/service-search-req
 * @description bluez-e79417ed7185b150a056d4eb3a1ab528b91d2fc0-src/sdpd-request.c-service_search_req CVE-2021-41229
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcstate_362, Initializer target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("sdp_get_cached_rsp")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vcstate_362
}

predicate func_4(Variable vcstate_362) {
	exists(AddressOfExpr target_4 |
		target_4.getOperand().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_4.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("sdp_cstate_get")
		and target_4.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vcstate_362)
}

predicate func_6(Function func) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("sdp_cont_info_free")
		and target_6.getArgument(0).(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_6.getEnclosingFunction() = func)
}

predicate func_8(Variable vcstate_362, BlockStmt target_22, IfStmt target_23, ExprStmt target_24) {
	exists(RelationalOperation target_8 |
		 (target_8 instanceof GEExpr or target_8 instanceof LEExpr)
		and target_8.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="maxBytesSent"
		and target_8.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_8.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_362
		and target_8.getLesserOperand().(ValueFieldAccess).getTarget().getName()="data_size"
		and target_8.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_8.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_8.getParent().(IfStmt).getThen()=target_22
		and target_23.getCondition().(VariableAccess).getLocation().isBefore(target_8.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getGreaterOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_9(Variable vpCacheBuffer_363, VariableAccess target_20, ExprStmt target_25) {
	exists(ExprStmt target_9 |
		target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCacheBuffer_363
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="data"
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_9.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_9
		and target_9.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_20
		and target_9.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_10(Function func) {
	exists(ValueFieldAccess target_10 |
		target_10.getTarget().getName()="data"
		and target_10.getQualifier().(PointerFieldAccess).getTarget().getName()="buf"
		and target_10.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_10.getEnclosingFunction() = func)
}

*/
predicate func_11(Variable vstatus_358, EqualityOperation target_15, ExprStmt target_26, ReturnStmt target_27) {
	exists(ExprStmt target_11 |
		target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_358
		and target_11.getExpr().(AssignExpr).getRValue().(Literal).getValue()="5"
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_11
		and target_11.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_11.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_27.getExpr().(VariableAccess).getLocation()))
}

predicate func_12(EqualityOperation target_15, Function func) {
	exists(GotoStmt target_12 |
		target_12.toString() = "goto ..."
		and target_12.getName() ="done"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_12
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
		and target_12.getEnclosingFunction() = func)
}

predicate func_13(LogicalOrExpr target_28, Function func) {
	exists(IfStmt target_13 |
		target_13.getCondition() instanceof EqualityOperation
		and target_13.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_13.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sdp_cont_info_free")
		and target_13.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("sdp_cont_info_t *")
		and target_13.getElse() instanceof BlockStmt
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(8)=target_13
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_28
		and target_13.getEnclosingFunction() = func)
}

predicate func_14(Variable vstatus_358, VariableAccess target_20, BlockStmt target_14) {
		target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_358
		and target_14.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="5"
		and target_14.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_14.getStmt(1).(GotoStmt).getName() ="done"
		and target_14.getParent().(IfStmt).getCondition()=target_20
}

predicate func_15(Variable vi_358, Variable vrsp_count_360, BlockStmt target_22, EqualityOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vi_358
		and target_15.getAnOperand().(VariableAccess).getTarget()=vrsp_count_360
		and target_15.getParent().(IfStmt).getThen()=target_22
}

predicate func_16(Parameter vbuf_356, EqualityOperation target_15, ExprStmt target_16) {
		target_16.getExpr().(FunctionCall).getTarget().hasName("sdp_set_cstate_pdu")
		and target_16.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_356
		and target_16.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_16.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_15
}

predicate func_17(Parameter vbuf_356, Variable vi_358, Variable vcstate_362, Variable vcStateId_365, Variable vnewState_526, EqualityOperation target_15, BlockStmt target_17) {
		target_17.getStmt(1).(EmptyStmt).toString() = ";"
		and target_17.getStmt(2).(IfStmt).getCondition().(VariableAccess).getTarget()=vcstate_362
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnewState_526
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vcstate_362
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_17.getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="8"
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnewState_526
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="8"
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="timestamp"
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewState_526
		and target_17.getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcStateId_365
		and target_17.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lastIndexSent"
		and target_17.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="cStateValue"
		and target_17.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vnewState_526
		and target_17.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vi_358
		and target_17.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("sdp_set_cstate_pdu")
		and target_17.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_356
		and target_17.getStmt(4).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnewState_526
		and target_17.getParent().(IfStmt).getCondition()=target_15
}

predicate func_18(Variable vcstate_362, VariableAccess target_18) {
		target_18.getTarget()=vcstate_362
		and target_18.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("sdp_get_cached_rsp")
}

predicate func_20(Variable vpCache_475, BlockStmt target_29, ExprStmt target_30, VariableAccess target_20) {
		target_20.getTarget()=vpCache_475
		and target_20.getParent().(IfStmt).getThen()=target_29
		and target_20.getLocation().isBefore(target_30.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_21(Variable vpCache_475, PointerFieldAccess target_21) {
		target_21.getTarget().getName()="data"
		and target_21.getQualifier().(VariableAccess).getTarget()=vpCache_475
}

predicate func_22(BlockStmt target_22) {
		target_22.getStmt(0) instanceof ExprStmt
}

predicate func_23(Parameter vbuf_356, Variable vrsp_count_360, Variable vcstate_362, Variable vpCacheBuffer_363, Variable vpCache_475, IfStmt target_23) {
		target_23.getCondition().(VariableAccess).getTarget()=vcstate_362
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(VariableAccess).getTarget()=vpCache_475
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCacheBuffer_363
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrsp_count_360
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_be16")
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="lastIndexSent"
		and target_23.getThen().(BlockStmt).getStmt(1).(IfStmt).getElse() instanceof BlockStmt
		and target_23.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCacheBuffer_363
		and target_23.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_23.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbuf_356
		and target_23.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_24(Variable vcstate_362, ExprStmt target_24) {
		target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="lastIndexSent"
		and target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="cStateValue"
		and target_24.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcstate_362
}

predicate func_25(Variable vrsp_count_360, Variable vpCacheBuffer_363, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrsp_count_360
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_be16")
		and target_25.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpCacheBuffer_363
}

predicate func_26(Variable vstatus_358, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vstatus_358
		and target_26.getExpr().(AssignExpr).getRValue().(Literal).getValue()="5"
}

predicate func_27(Variable vstatus_358, ReturnStmt target_27) {
		target_27.getExpr().(VariableAccess).getTarget()=vstatus_358
}

predicate func_28(Variable vcstate_362, Variable vcStateId_365, LogicalOrExpr target_28) {
		target_28.getAnOperand().(VariableAccess).getTarget()=vcstate_362
		and target_28.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcStateId_365
		and target_28.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
}

predicate func_29(Variable vrsp_count_360, Variable vpCacheBuffer_363, Variable vpCache_475, BlockStmt target_29) {
		target_29.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCacheBuffer_363
		and target_29.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_29.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpCache_475
		and target_29.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrsp_count_360
		and target_29.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_be16")
		and target_29.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpCacheBuffer_363
}

predicate func_30(Variable vpCacheBuffer_363, Variable vpCache_475, ExprStmt target_30) {
		target_30.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpCacheBuffer_363
		and target_30.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="data"
		and target_30.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpCache_475
}

from Function func, Parameter vbuf_356, Variable vstatus_358, Variable vi_358, Variable vrsp_count_360, Variable vcstate_362, Variable vpCacheBuffer_363, Variable vcStateId_365, Variable vpCache_475, Variable vnewState_526, Initializer target_0, BlockStmt target_14, EqualityOperation target_15, ExprStmt target_16, BlockStmt target_17, VariableAccess target_18, VariableAccess target_20, PointerFieldAccess target_21, BlockStmt target_22, IfStmt target_23, ExprStmt target_24, ExprStmt target_25, ExprStmt target_26, ReturnStmt target_27, LogicalOrExpr target_28, BlockStmt target_29, ExprStmt target_30
where
func_0(vcstate_362, target_0)
and not func_4(vcstate_362)
and not func_6(func)
and not func_8(vcstate_362, target_22, target_23, target_24)
and not func_9(vpCacheBuffer_363, target_20, target_25)
and not func_11(vstatus_358, target_15, target_26, target_27)
and not func_12(target_15, func)
and not func_13(target_28, func)
and func_14(vstatus_358, target_20, target_14)
and func_15(vi_358, vrsp_count_360, target_22, target_15)
and func_16(vbuf_356, target_15, target_16)
and func_17(vbuf_356, vi_358, vcstate_362, vcStateId_365, vnewState_526, target_15, target_17)
and func_18(vcstate_362, target_18)
and func_20(vpCache_475, target_29, target_30, target_20)
and func_21(vpCache_475, target_21)
and func_22(target_22)
and func_23(vbuf_356, vrsp_count_360, vcstate_362, vpCacheBuffer_363, vpCache_475, target_23)
and func_24(vcstate_362, target_24)
and func_25(vrsp_count_360, vpCacheBuffer_363, target_25)
and func_26(vstatus_358, target_26)
and func_27(vstatus_358, target_27)
and func_28(vcstate_362, vcStateId_365, target_28)
and func_29(vrsp_count_360, vpCacheBuffer_363, vpCache_475, target_29)
and func_30(vpCacheBuffer_363, vpCache_475, target_30)
and vbuf_356.getType().hasName("sdp_buf_t *")
and vstatus_358.getType().hasName("int")
and vi_358.getType().hasName("int")
and vrsp_count_360.getType().hasName("uint16_t")
and vcstate_362.getType().hasName("sdp_cont_state_t *")
and vpCacheBuffer_363.getType().hasName("uint8_t *")
and vcStateId_365.getType().hasName("uint32_t")
and vpCache_475.getType().hasName("sdp_buf_t *")
and vnewState_526.getType().hasName("sdp_cont_state_t")
and vbuf_356.getParentScope+() = func
and vstatus_358.getParentScope+() = func
and vi_358.getParentScope+() = func
and vrsp_count_360.getParentScope+() = func
and vcstate_362.getParentScope+() = func
and vpCacheBuffer_363.getParentScope+() = func
and vcStateId_365.getParentScope+() = func
and vpCache_475.getParentScope+() = func
and vnewState_526.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
