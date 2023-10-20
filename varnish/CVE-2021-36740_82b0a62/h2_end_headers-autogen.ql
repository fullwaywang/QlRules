/**
 * @name varnish-82b0a629f60136e76112c6f2c6372cce77b683be-h2_end_headers
 * @id cpp/varnish/82b0a629f60136e76112c6f2c6372cce77b683be/h2-end-headers
 * @description varnish-82b0a629f60136e76112c6f2c6372cce77b683be-bin/varnishd/http2/cache_http2_proto.c-h2_end_headers CVE-2021-36740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ssize_t")
		and target_0.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

predicate func_1(Variable v__func__, ExprStmt target_17, ExprStmt target_18, Function func) {
	exists(DoStmt target_1 |
		target_1.getCondition() instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(UnaryMinusExpr).getValue()="-2"
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cl >= -2"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_1)
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(ExprStmt target_19, Function func) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_2.getLesserOperand().(UnaryMinusExpr).getValue()="-2"
		and target_2.getParent().(NotExpr).getOperand() instanceof FunctionCall
		and target_2.getParent().(NotExpr).getParent().(IfStmt).getThen()=target_19
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Variable v__func__, EqualityOperation target_10, ExprStmt target_17, ExprStmt target_18) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_3.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_3.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="cl >= -2"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_4(BlockStmt target_20, Function func) {
	exists(EqualityOperation target_4 |
		target_4.getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_4.getAnOperand().(UnaryMinusExpr).getValue()="-2"
		and target_4.getParent().(IfStmt).getThen()=target_20
		and target_4.getEnclosingFunction() = func)
}

predicate func_5(Parameter vh2_553, EqualityOperation target_10, AddressOfExpr target_21, ExprStmt target_22) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_553
		and target_5.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Non-parseable Content-Length"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(EqualityOperation target_10, Function func) {
	exists(ReturnStmt target_6 |
		target_6.getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(1)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
		and target_6.getEnclosingFunction() = func)
}

predicate func_7(Parameter vreq_554, Variable vBS_EOF, Variable vH2CE_PROTOCOL_ERROR, ArrayExpr target_24, Function func) {
	exists(IfStmt target_7 |
		target_7.getCondition() instanceof EqualityOperation
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vBS_EOF
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getElse() instanceof ExprStmt
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="content_length"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="htc"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("ssize_t")
		and target_7.getElse().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_7.getElse().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_7.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_7.getElse().(BlockStmt).getStmt(2).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_7.getElse().(BlockStmt).getStmt(2).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vH2CE_PROTOCOL_ERROR
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_7 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_7)
		and target_7.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_8(ReturnStmt target_25, Function func) {
	exists(EqualityOperation target_8 |
		target_8.getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_8.getAnOperand().(UnaryMinusExpr).getValue()="-1"
		and target_8.getParent().(IfStmt).getThen()=target_25
		and target_8.getEnclosingFunction() = func)
}

*/
predicate func_10(Parameter vreq_554, BlockStmt target_20, EqualityOperation target_10) {
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_10.getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(IfStmt).getThen()=target_20
}

predicate func_11(Parameter vreq_554, Variable vBS_LENGTH, NotExpr target_26, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vBS_LENGTH
		and target_11.getParent().(IfStmt).getCondition()=target_26
}

predicate func_12(Parameter vr2_554, EqualityOperation target_10, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_554
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_10
}

predicate func_13(Parameter vreq_554, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="http"
		and target_13.getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_13.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_14(Parameter vreq_554, FunctionCall target_14) {
		target_14.getTarget().hasName("http_GetContentLength")
		and target_14.getArgument(0).(PointerFieldAccess).getTarget().getName()="http"
		and target_14.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
}

predicate func_16(Parameter vreq_554, Variable vH_Content_Length, FunctionCall target_16) {
		target_16.getTarget().hasName("http_GetHdr")
		and target_16.getArgument(0).(PointerFieldAccess).getTarget().getName()="http"
		and target_16.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_16.getArgument(1).(VariableAccess).getTarget()=vH_Content_Length
		and target_16.getArgument(2) instanceof Literal
}

predicate func_17(Variable v__func__, ExprStmt target_17) {
		target_17.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_17.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_17.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_17.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_17.getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
}

predicate func_18(Variable v__func__, ExprStmt target_18) {
		target_18.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_18.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_18.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_18.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_18.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="req->req_body_status == BS_NONE"
}

predicate func_19(Parameter vreq_554, Variable vBS_EOF, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_19.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vBS_EOF
}

predicate func_20(Parameter vreq_554, Variable vBS_EOF, BlockStmt target_20) {
		target_20.getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand() instanceof FunctionCall
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="req_body_status"
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
		and target_20.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vBS_EOF
		and target_20.getStmt(0).(IfStmt).getElse() instanceof ExprStmt
}

predicate func_21(Parameter vh2_553, AddressOfExpr target_21) {
		target_21.getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_21.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_553
}

predicate func_22(Parameter vh2_553, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_22.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_553
		and target_22.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Missing :method"
}

predicate func_24(Parameter vreq_554, ArrayExpr target_24) {
		target_24.getArrayBase().(PointerFieldAccess).getTarget().getName()="hd"
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="http"
		and target_24.getArrayBase().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vreq_554
}

predicate func_25(Variable vH2CE_PROTOCOL_ERROR, ReturnStmt target_25) {
		target_25.getExpr().(VariableAccess).getTarget()=vH2CE_PROTOCOL_ERROR
}

predicate func_26(NotExpr target_26) {
		target_26.getOperand() instanceof FunctionCall
}

from Function func, Parameter vh2_553, Parameter vreq_554, Parameter vr2_554, Variable v__func__, Variable vH_Content_Length, Variable vBS_EOF, Variable vBS_LENGTH, Variable vH2CE_PROTOCOL_ERROR, EqualityOperation target_10, ExprStmt target_11, ExprStmt target_12, PointerFieldAccess target_13, FunctionCall target_14, FunctionCall target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, BlockStmt target_20, AddressOfExpr target_21, ExprStmt target_22, ArrayExpr target_24, ReturnStmt target_25, NotExpr target_26
where
not func_0(func)
and not func_1(v__func__, target_17, target_18, func)
and not func_4(target_20, func)
and not func_5(vh2_553, target_10, target_21, target_22)
and not func_6(target_10, func)
and not func_7(vreq_554, vBS_EOF, vH2CE_PROTOCOL_ERROR, target_24, func)
and func_10(vreq_554, target_20, target_10)
and func_11(vreq_554, vBS_LENGTH, target_26, target_11)
and func_12(vr2_554, target_10, target_12)
and func_13(vreq_554, target_13)
and func_14(vreq_554, target_14)
and func_16(vreq_554, vH_Content_Length, target_16)
and func_17(v__func__, target_17)
and func_18(v__func__, target_18)
and func_19(vreq_554, vBS_EOF, target_19)
and func_20(vreq_554, vBS_EOF, target_20)
and func_21(vh2_553, target_21)
and func_22(vh2_553, target_22)
and func_24(vreq_554, target_24)
and func_25(vH2CE_PROTOCOL_ERROR, target_25)
and func_26(target_26)
and vh2_553.getType().hasName("h2_sess *")
and vreq_554.getType().hasName("req *")
and vr2_554.getType().hasName("h2_req *")
and v__func__.getType() instanceof ArrayType
and vH_Content_Length.getType() instanceof ArrayType
and vBS_EOF.getType() instanceof ArrayType
and vBS_LENGTH.getType() instanceof ArrayType
and vH2CE_PROTOCOL_ERROR.getType() instanceof ArrayType
and vh2_553.getParentScope+() = func
and vreq_554.getParentScope+() = func
and vr2_554.getParentScope+() = func
and not v__func__.getParentScope+() = func
and not vH_Content_Length.getParentScope+() = func
and not vBS_EOF.getParentScope+() = func
and not vBS_LENGTH.getParentScope+() = func
and not vH2CE_PROTOCOL_ERROR.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
