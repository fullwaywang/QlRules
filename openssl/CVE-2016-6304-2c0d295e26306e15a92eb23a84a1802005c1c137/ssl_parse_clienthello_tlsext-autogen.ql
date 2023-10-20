/**
 * @name openssl-2c0d295e26306e15a92eb23a84a1802005c1c137-ssl_parse_clienthello_tlsext
 * @id cpp/openssl/2c0d295e26306e15a92eb23a84a1802005c1c137/ssl-parse-clienthello-tlsext
 * @description openssl-2c0d295e26306e15a92eb23a84a1802005c1c137-ssl/t1_lib.c-ssl_parse_clienthello_tlsext CVE-2016-6304
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_984, EqualityOperation target_25, LogicalAndExpr target_24) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("sk_pop_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_0.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_0.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_0.getExpr().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25
		and target_0.getExpr().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_984, EqualityOperation target_25) {
	exists(IfStmt target_1 |
		target_1.getCondition() instanceof RelationalOperation
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr() instanceof AssignExpr
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_1.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(6)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_25)
}

/*predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr() instanceof AssignExpr
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Parameter vs_984, BlockStmt target_26, LogicalAndExpr target_24) {
	exists(EqualityOperation target_3 |
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_3.getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_26
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_4(Parameter val_985, LogicalAndExpr target_24, NotExpr target_27, ExprStmt target_28) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val_985
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_27.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_28.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

*/
predicate func_5(Variable vdsize_1281, RelationalOperation target_29, RelationalOperation target_7) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vdsize_1281
		and target_5.getLesserOperand().(Literal).getValue()="0"
		and target_29.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation())
		and target_5.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_7(Variable vdsize_1281, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vdsize_1281
		and target_7.getLesserOperand().(Literal).getValue()="0"
}

predicate func_10(Variable vdsize_1281, IfStmt target_10) {
		target_10.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdsize_1281
		and target_10.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_10.getThen().(GotoStmt).toString() = "goto ..."
		and target_10.getThen().(GotoStmt).getName() ="err"
}

predicate func_11(Variable vdata_990, Variable vidsize_1289, ExprStmt target_11) {
		target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vidsize_1289
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdata_990
		and target_11.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_11.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_990
		and target_11.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_12(Variable vdsize_1281, Variable vidsize_1289, ExprStmt target_12) {
		target_12.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vdsize_1281
		and target_12.getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_12.getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vidsize_1289
}

predicate func_13(Variable vsize_988, Variable vidsize_1289, ExprStmt target_13) {
		target_13.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vsize_988
		and target_13.getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_13.getExpr().(AssignSubExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vidsize_1289
}

predicate func_14(Variable vdsize_1281, IfStmt target_14) {
		target_14.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vdsize_1281
		and target_14.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_14.getThen().(GotoStmt).toString() = "goto ..."
		and target_14.getThen().(GotoStmt).getName() ="err"
}

predicate func_15(Variable vdata_990, Variable vsdata_1280, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsdata_1280
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vdata_990
}

predicate func_16(Variable vdata_990, Variable vidsize_1289, ExprStmt target_16) {
		target_16.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vdata_990
		and target_16.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vidsize_1289
}

predicate func_17(Variable vsdata_1280, Variable vid_1288, Variable vidsize_1289, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vid_1288
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("d2i_OCSP_RESPID")
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="0"
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vsdata_1280
		and target_17.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vidsize_1289
}

predicate func_18(Variable vid_1288, IfStmt target_18) {
		target_18.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vid_1288
		and target_18.getThen().(GotoStmt).toString() = "goto ..."
		and target_18.getThen().(GotoStmt).getName() ="err"
}

predicate func_19(Variable vdata_990, Variable vsdata_1280, Variable vid_1288, IfStmt target_19) {
		target_19.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vdata_990
		and target_19.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsdata_1280
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_19.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid_1288
		and target_19.getThen().(BlockStmt).getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_19.getThen().(BlockStmt).getStmt(1).(GotoStmt).getName() ="err"
}

predicate func_20(Parameter val_985, Variable vid_1288, Parameter vs_984, IfStmt target_20) {
		target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("sk_push")
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getCondition().(Literal).getValue()="1"
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getThen().(VariableAccess).getTarget()=vid_1288
		and target_20.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(ConditionalExpr).getElse().(Literal).getValue()="0"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid_1288
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val_985
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_20.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_21(Function func, ReturnStmt target_21) {
		target_21.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_21
}

predicate func_22(Parameter vs_984, PointerFieldAccess target_22) {
		target_22.getTarget().getName()="tlsext_ocsp_ids"
		and target_22.getQualifier().(VariableAccess).getTarget()=vs_984
}

predicate func_23(Parameter vs_984, AssignExpr target_23) {
		target_23.getLValue().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_23.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_23.getRValue().(FunctionCall).getTarget().hasName("sk_new_null")
}

predicate func_24(Parameter vs_984, BlockStmt target_26, LogicalAndExpr target_24) {
		target_24.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="tlsext_ocsp_ids"
		and target_24.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_24.getAnOperand().(NotExpr).getOperand() instanceof AssignExpr
		and target_24.getParent().(IfStmt).getThen()=target_26
}

predicate func_25(Parameter vs_984, EqualityOperation target_25) {
		target_25.getAnOperand().(PointerFieldAccess).getTarget().getName()="tlsext_status_type"
		and target_25.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_984
		and target_25.getAnOperand().(Literal).getValue()="1"
}

predicate func_26(Parameter val_985, Variable vid_1288, BlockStmt target_26) {
		target_26.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("OCSP_RESPID_free")
		and target_26.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vid_1288
		and target_26.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val_985
		and target_26.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
		and target_26.getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_27(Parameter val_985, Variable vsize_988, Variable vdata_990, Parameter vs_984, NotExpr target_27) {
		target_27.getOperand().(FunctionCall).getTarget().hasName("ssl_parse_clienthello_renegotiate_ext")
		and target_27.getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_984
		and target_27.getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vdata_990
		and target_27.getOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vsize_988
		and target_27.getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=val_985
}

predicate func_28(Parameter val_985, ExprStmt target_28) {
		target_28.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=val_985
		and target_28.getExpr().(AssignExpr).getRValue().(Literal).getValue()="80"
}

predicate func_29(Variable vsize_988, Variable vdsize_1281, RelationalOperation target_29) {
		 (target_29 instanceof GTExpr or target_29 instanceof LTExpr)
		and target_29.getGreaterOperand().(VariableAccess).getTarget()=vdsize_1281
		and target_29.getLesserOperand().(VariableAccess).getTarget()=vsize_988
}

from Function func, Parameter val_985, Variable vsize_988, Variable vdata_990, Variable vsdata_1280, Variable vdsize_1281, Variable vid_1288, Parameter vs_984, Variable vidsize_1289, RelationalOperation target_7, IfStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, IfStmt target_14, ExprStmt target_15, ExprStmt target_16, ExprStmt target_17, IfStmt target_18, IfStmt target_19, IfStmt target_20, ReturnStmt target_21, PointerFieldAccess target_22, AssignExpr target_23, LogicalAndExpr target_24, EqualityOperation target_25, BlockStmt target_26, NotExpr target_27, ExprStmt target_28, RelationalOperation target_29
where
not func_0(vs_984, target_25, target_24)
and not func_1(vs_984, target_25)
and not func_5(vdsize_1281, target_29, target_7)
and func_7(vdsize_1281, target_7)
and func_10(vdsize_1281, target_10)
and func_11(vdata_990, vidsize_1289, target_11)
and func_12(vdsize_1281, vidsize_1289, target_12)
and func_13(vsize_988, vidsize_1289, target_13)
and func_14(vdsize_1281, target_14)
and func_15(vdata_990, vsdata_1280, target_15)
and func_16(vdata_990, vidsize_1289, target_16)
and func_17(vsdata_1280, vid_1288, vidsize_1289, target_17)
and func_18(vid_1288, target_18)
and func_19(vdata_990, vsdata_1280, vid_1288, target_19)
and func_20(val_985, vid_1288, vs_984, target_20)
and func_21(func, target_21)
and func_22(vs_984, target_22)
and func_23(vs_984, target_23)
and func_24(vs_984, target_26, target_24)
and func_25(vs_984, target_25)
and func_26(val_985, vid_1288, target_26)
and func_27(val_985, vsize_988, vdata_990, vs_984, target_27)
and func_28(val_985, target_28)
and func_29(vsize_988, vdsize_1281, target_29)
and val_985.getType().hasName("int *")
and vsize_988.getType().hasName("unsigned short")
and vdata_990.getType().hasName("unsigned char *")
and vsdata_1280.getType().hasName("const unsigned char *")
and vdsize_1281.getType().hasName("int")
and vid_1288.getType().hasName("OCSP_RESPID *")
and vs_984.getType().hasName("SSL *")
and vidsize_1289.getType().hasName("int")
and val_985.getParentScope+() = func
and vsize_988.getParentScope+() = func
and vdata_990.getParentScope+() = func
and vsdata_1280.getParentScope+() = func
and vdsize_1281.getParentScope+() = func
and vid_1288.getParentScope+() = func
and vs_984.getParentScope+() = func
and vidsize_1289.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
