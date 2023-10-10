/**
 * @name varnish-9be22198e258d0e7a5c41f4291792214a29405cf-h2_end_headers
 * @id cpp/varnish/9be22198e258d0e7a5c41f4291792214a29405cf/h2-end-headers
 * @description varnish-9be22198e258d0e7a5c41f4291792214a29405cf-bin/varnishd/http2/cache_http2_proto.c-h2_end_headers CVE-2021-36740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ssize_t")
		and target_1.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1))
}

predicate func_2(Variable v__func__, ExprStmt target_17, ExprStmt target_18, Function func) {
	exists(DoStmt target_2 |
		target_2.getCondition() instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-2"
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cl >= -2"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2)
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_3(ExprStmt target_19, Function func) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GEExpr or target_3 instanceof LEExpr)
		and target_3.getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_3.getLesserOperand().(UnaryMinusExpr).getValue()="-2"
		and target_3.getParent().(NotExpr).getOperand() instanceof FunctionCall
		and target_3.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_19
		and target_3.getEnclosingFunction() = func)
}

*/
/*predicate func_4(Variable v__func__, EqualityOperation target_11, ExprStmt target_17, ExprStmt target_18) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cl >= -2"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_5(BlockStmt target_20, Function func) {
	exists(EqualityOperation target_5 |
		target_5.getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_5.getAnOperand().(UnaryMinusExpr).getValue()="-2"
		and target_5.getParent().(IfStmt).getThen()=target_20
		and target_5.getEnclosingFunction() = func)
}

predicate func_6(Parameter vh2_545, EqualityOperation target_11, AddressOfExpr target_21, ExprStmt target_22) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_545
		and target_6.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Non-parseable Content-Length"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(EqualityOperation target_11, Function func) {
	exists(ReturnStmt target_7 |
		target_7.getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_11
		and target_7.getEnclosingFunction() = func)
}

predicate func_8(Parameter vreq_546, Parameter vr2_546, Variable vH2CE_PROTOCOL_ERROR, ArrayExpr target_24, ExprStmt target_25, ExprStmt target_26, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition() instanceof EqualityOperation
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse() instanceof ExprStmt
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content_length"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="htc"
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_8.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("ssize_t")
		and target_8.getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_546
		and target_8.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_8.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_8.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vH2CE_PROTOCOL_ERROR
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_8)
		and target_8.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_8.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_9(ReturnStmt target_27, Function func) {
	exists(EqualityOperation target_9 |
		target_9.getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_9.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_9.getParent().(IfStmt).getThen()=target_27
		and target_9.getEnclosingFunction() = func)
}

*/
predicate func_11(Parameter vreq_546, BlockStmt target_20, EqualityOperation target_11) {
		target_11.getAnOperand().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_11.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_11.getParent().(IfStmt).getThen()=target_20
}

predicate func_12(Parameter vreq_546, NotExpr target_28, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_12.getParent().(IfStmt).getCondition()=target_28
}

predicate func_13(Parameter vreq_546, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="http"
		and target_13.getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_13.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_14(Parameter vreq_546, FunctionCall target_14) {
		target_14.getTarget().hasName("http_GetContentLength")
		and target_14.getArgument(0).(PointerFieldAccess).getTarget().getName()="http"
		and target_14.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
}

predicate func_16(Parameter vreq_546, Variable vb_549, Variable vH_Content_Length, FunctionCall target_16) {
		target_16.getTarget().hasName("http_GetHdr")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="http"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_16.getArgument(1).(VariableAccess).getTarget()=vH_Content_Length
		and target_16.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vb_549
}

predicate func_17(Variable v__func__, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_17.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_17.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_17.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="(r2->req->ws->r) == 0"
}

predicate func_18(Variable v__func__, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_18.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="req->req_body_status == REQ_BODY_NONE"
}

predicate func_19(Parameter vreq_546, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
}

predicate func_20(Parameter vreq_546, BlockStmt target_20) {
		target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
		and target_20.getStmt(0).(IfStmt).getElse() instanceof ExprStmt
}

predicate func_21(Parameter vh2_545, AddressOfExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_545
}

predicate func_22(Parameter vh2_545, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_545
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Missing :method"
}

predicate func_24(Parameter vreq_546, ArrayExpr target_24) {
		target_24.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http"
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_546
}

predicate func_25(Parameter vr2_546, ExprStmt target_25) {
		target_25.getExpr().(FunctionCall).getTarget().hasName("h2_del_req")
		and target_25.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vr2_546
}

predicate func_26(Parameter vr2_546, ExprStmt target_26) {
		target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="scheduled"
		and target_26.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_546
		and target_26.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_27(Variable vH2CE_PROTOCOL_ERROR, ReturnStmt target_27) {
		target_27.getExpr().(VariableAccess).getTarget()=vH2CE_PROTOCOL_ERROR
}

predicate func_28(NotExpr target_28) {
		target_28.getOperand() instanceof FunctionCall
}

from Function func, Parameter vh2_545, Parameter vreq_546, Parameter vr2_546, Variable vb_549, Variable v__func__, Variable vH_Content_Length, Variable vH2CE_PROTOCOL_ERROR, EqualityOperation target_11, ExprStmt target_12, PointerFieldAccess target_13, FunctionCall target_14, FunctionCall target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, BlockStmt target_20, AddressOfExpr target_21, ExprStmt target_22, ArrayExpr target_24, ExprStmt target_25, ExprStmt target_26, ReturnStmt target_27, NotExpr target_28
where
not func_1(func)
and not func_2(v__func__, target_17, target_18, func)
and not func_5(target_20, func)
and not func_6(vh2_545, target_11, target_21, target_22)
and not func_7(target_11, func)
and not func_8(vreq_546, vr2_546, vH2CE_PROTOCOL_ERROR, target_24, target_25, target_26, func)
and func_11(vreq_546, target_20, target_11)
and func_12(vreq_546, target_28, target_12)
and func_13(vreq_546, target_13)
and func_14(vreq_546, target_14)
and func_16(vreq_546, vb_549, vH_Content_Length, target_16)
and func_17(v__func__, target_17)
and func_18(v__func__, target_18)
and func_19(vreq_546, target_19)
and func_20(vreq_546, target_20)
and func_21(vh2_545, target_21)
and func_22(vh2_545, target_22)
and func_24(vreq_546, target_24)
and func_25(vr2_546, target_25)
and func_26(vr2_546, target_26)
and func_27(vH2CE_PROTOCOL_ERROR, target_27)
and func_28(target_28)
and vh2_545.getType().hasName("h2_sess *")
and vreq_546.getType().hasName("req *")
and vr2_546.getType().hasName("h2_req *")
and vb_549.getType().hasName("const char *")
and v__func__.getType() instanceof ArrayType
and vH_Content_Length.getType() instanceof ArrayType
and vH2CE_PROTOCOL_ERROR.getType() instanceof ArrayType
and vh2_545.getParentScope+() = func
and vreq_546.getParentScope+() = func
and vr2_546.getParentScope+() = func
and vb_549.getParentScope+() = func
and not v__func__.getParentScope+() = func
and not vH_Content_Length.getParentScope+() = func
and not vH2CE_PROTOCOL_ERROR.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
