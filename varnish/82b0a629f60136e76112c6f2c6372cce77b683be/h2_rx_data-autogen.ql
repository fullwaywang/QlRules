/**
 * @name varnish-82b0a629f60136e76112c6f2c6372cce77b683be-h2_rx_data
 * @id cpp/varnish/82b0a629f60136e76112c6f2c6372cce77b683be/h2-rx-data
 * @description varnish-82b0a629f60136e76112c6f2c6372cce77b683be-bin/varnishd/http2/cache_http2_proto.c-h2_rx_data CVE-2021-36740
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vh2_735, Parameter vr2_735, ConditionalExpr target_6, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="reqbody_bytes"
		and target_0.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_0.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rxf_len"
		and target_0.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_0)
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vh2_735, Parameter vr2_735, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rxf_flags"
		and target_1.getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_1.getCondition().(BitwiseAndExpr).getRightOperand().(VariableAccess).getType().hasName("uint8_t")
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="state"
		and target_1.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Parameter vr2_735, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("ssize_t")
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="content_length"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="htc"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req"
		and target_2.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_2))
}

predicate func_3(Parameter vh2_735, Parameter vr2_735, Variable v__func__, NotExpr target_7, NotExpr target_8, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="reqbody_bytes"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="state"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="reqbody_bytes"
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("ssize_t")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("VSLb")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="vsl"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="H2: stream %u: Received data and Content-Length mismatch"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rxf_stream"
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="error"
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_3.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="cond"
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(DoStmt).getCondition() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("Lck__Unlock")
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_3.getThen().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_3.getThen().(BlockStmt).getStmt(4).(ReturnStmt).getExpr().(VariableAccess).getType().hasName("const h2_error_s[1]")
		and (func.getEntryPoint().(BlockStmt).getStmt(15)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(15).getFollowingStmt()=target_3)
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vr2_735, ExprStmt target_9, Function func) {
	exists(IfStmt target_4 |
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="cond"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_4.getThen().(DoStmt).getCondition() instanceof Literal
		and target_4.getThen().(DoStmt).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(20)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(20).getFollowingStmt()=target_4)
		and target_9.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vh2_735, Variable v__func__, ExprStmt target_10, AddressOfExpr target_11, ExprStmt target_12, ExprStmt target_13, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("Lck__Unlock")
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(25)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(25).getFollowingStmt()=target_5)
		and target_10.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vh2_735, Parameter vr2_735, ConditionalExpr target_6) {
		target_6.getCondition().(PointerFieldAccess).getTarget().getName()="error"
		and target_6.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_6.getThen().(PointerFieldAccess).getTarget().getName()="error"
		and target_6.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_6.getElse().(PointerFieldAccess).getTarget().getName()="error"
		and target_6.getElse().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
}

predicate func_7(Parameter vh2_735, NotExpr target_7) {
		target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="mailcall"
		and target_7.getOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_7.getOperand().(EqualityOperation).getAnOperand() instanceof Literal
}

predicate func_8(Parameter vr2_735, NotExpr target_8) {
		target_8.getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("pthread_cond_signal")
		and target_8.getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="cond"
		and target_8.getOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_8.getOperand().(EqualityOperation).getAnOperand() instanceof Literal
}

predicate func_9(Parameter vh2_735, Parameter vr2_735, ExprStmt target_9) {
		target_9.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getTarget().getName()="r_window"
		and target_9.getExpr().(AssignSubExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vr2_735
		and target_9.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getTarget().getName()="rxf_len"
		and target_9.getExpr().(AssignSubExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
}

predicate func_10(Parameter vh2_735, ExprStmt target_10) {
		target_10.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="r_window"
		and target_10.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="req0"
		and target_10.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
}

predicate func_11(Parameter vh2_735, AddressOfExpr target_11) {
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
}

predicate func_12(Variable v__func__, ExprStmt target_12) {
		target_12.getExpr().(FunctionCall).getTarget().hasName("VAS_Fail")
		and target_12.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=v__func__
		and target_12.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_12.getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_12.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="(Lck_CondWait(h2->cond, &h2->sess->mtx, 0)) == 0"
}

predicate func_13(Parameter vh2_735, Variable v__func__, ExprStmt target_13) {
		target_13.getExpr().(FunctionCall).getTarget().hasName("Lck__Unlock")
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="mtx"
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="sess"
		and target_13.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vh2_735
		and target_13.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=v__func__
		and target_13.getExpr().(FunctionCall).getArgument(2) instanceof Literal
}

from Function func, Parameter vh2_735, Parameter vr2_735, Variable v__func__, ConditionalExpr target_6, NotExpr target_7, NotExpr target_8, ExprStmt target_9, ExprStmt target_10, AddressOfExpr target_11, ExprStmt target_12, ExprStmt target_13
where
not func_0(vh2_735, vr2_735, target_6, func)
and not func_1(vh2_735, vr2_735, func)
and not func_2(vr2_735, func)
and not func_3(vh2_735, vr2_735, v__func__, target_7, target_8, func)
and not func_4(vr2_735, target_9, func)
and not func_5(vh2_735, v__func__, target_10, target_11, target_12, target_13, func)
and func_6(vh2_735, vr2_735, target_6)
and func_7(vh2_735, target_7)
and func_8(vr2_735, target_8)
and func_9(vh2_735, vr2_735, target_9)
and func_10(vh2_735, target_10)
and func_11(vh2_735, target_11)
and func_12(v__func__, target_12)
and func_13(vh2_735, v__func__, target_13)
and vh2_735.getType().hasName("h2_sess *")
and vr2_735.getType().hasName("h2_req *")
and v__func__.getType() instanceof ArrayType
and vh2_735.getParentScope+() = func
and vr2_735.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
