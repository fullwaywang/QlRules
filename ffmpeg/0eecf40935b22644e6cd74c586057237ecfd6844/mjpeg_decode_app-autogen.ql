/**
 * @name ffmpeg-0eecf40935b22644e6cd74c586057237ecfd6844-mjpeg_decode_app
 * @id cpp/ffmpeg/0eecf40935b22644e6cd74c586057237ecfd6844/mjpeg-decode-app
 * @description ffmpeg-0eecf40935b22644e6cd74c586057237ecfd6844-libavcodec/mjpegdec.c-mjpeg_decode_app CVE-2014-9316
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Parameter vs_1538, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15) {
	exists(IfStmt target_4 |
		target_4.getCondition().(PointerFieldAccess).getTarget().getName()="got_picture"
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="rgb"
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="pegasus_rct"
		and target_4.getThen().(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_4.getThen().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getThen().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_4.getThen().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_4.getThen().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="24"
		and target_4.getThen().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Mismatching LJIF tag\n"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(9)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Parameter vs_1538, EqualityOperation target_13, AddressOfExpr target_16, ExprStmt target_17) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rgb"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_16.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vs_1538, EqualityOperation target_13, ExprStmt target_18, ExprStmt target_19) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pegasus_rct"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("int")
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(11)=target_6
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vs_1538, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="rgb"
		and target_7.getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_7.getParent().(AssignExpr).getLValue() = target_7
		and target_7.getParent().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_8(Parameter vs_1538, PointerFieldAccess target_8) {
		target_8.getTarget().getName()="pegasus_rct"
		and target_8.getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_8.getParent().(AssignExpr).getLValue() = target_8
		and target_8.getParent().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_9(Parameter vs_1538, VariableAccess target_9) {
		target_9.getTarget()=vs_1538
}

predicate func_10(Parameter vs_1538, VariableAccess target_10) {
		target_10.getTarget()=vs_1538
}

predicate func_11(Parameter vs_1538, ExprStmt target_17, ExprStmt target_20, PointerFieldAccess target_11) {
		target_11.getTarget().getName()="rgb"
		and target_11.getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(VariableAccess).getLocation())
		and target_11.getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_12(Parameter vs_1538, ExprStmt target_19, ExprStmt target_14, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="pegasus_rct"
		and target_12.getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_12.getQualifier().(VariableAccess).getLocation())
		and target_12.getQualifier().(VariableAccess).getLocation().isBefore(target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_13(EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_13.getAnOperand().(FunctionCall).getTarget().hasName("av_bswap32")
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="l"
		and target_13.getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(StringLiteral).getValue()="LJIF"
}

predicate func_14(Parameter vs_1538, ExprStmt target_14) {
		target_14.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_14.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_14.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_14.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="unknown colorspace %d\n"
		and target_14.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_15(Parameter vs_1538, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colr"
		and target_15.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="8"
}

predicate func_16(Parameter vs_1538, AddressOfExpr target_16) {
		target_16.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_16.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
}

predicate func_17(Parameter vs_1538, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pegasus_rct"
		and target_17.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_17.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_18(Parameter vs_1538, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rgb"
		and target_18.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_18.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_19(Parameter vs_1538, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rgb"
		and target_19.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_19.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_20(Parameter vs_1538, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="pegasus_rct"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_1538
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

from Function func, Parameter vs_1538, PointerFieldAccess target_7, PointerFieldAccess target_8, VariableAccess target_9, VariableAccess target_10, PointerFieldAccess target_11, PointerFieldAccess target_12, EqualityOperation target_13, ExprStmt target_14, ExprStmt target_15, AddressOfExpr target_16, ExprStmt target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20
where
not func_4(vs_1538, target_13, target_14, target_15)
and not func_5(vs_1538, target_13, target_16, target_17)
and not func_6(vs_1538, target_13, target_18, target_19)
and func_7(vs_1538, target_7)
and func_8(vs_1538, target_8)
and func_9(vs_1538, target_9)
and func_10(vs_1538, target_10)
and func_11(vs_1538, target_17, target_20, target_11)
and func_12(vs_1538, target_19, target_14, target_12)
and func_13(target_13)
and func_14(vs_1538, target_14)
and func_15(vs_1538, target_15)
and func_16(vs_1538, target_16)
and func_17(vs_1538, target_17)
and func_18(vs_1538, target_18)
and func_19(vs_1538, target_19)
and func_20(vs_1538, target_20)
and vs_1538.getType().hasName("MJpegDecodeContext *")
and vs_1538.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
