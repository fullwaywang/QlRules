/**
 * @name ffmpeg-cfce16449cb815132f829d5a07beb138dfb2cba6-mpeg_mux_write_packet
 * @id cpp/ffmpeg/cfce16449cb815132f829d5a07beb138dfb2cba6/mpeg-mux-write-packet
 * @description ffmpeg-cfce16449cb815132f829d5a07beb138dfb2cba6-libavformat/mpegenc.c-mpeg_mux_write_packet CVE-2020-21697
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstream_1149, ExprStmt target_9, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="predecode_packet"
		and target_0.getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_0.getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
}

predicate func_1(Variable vstream_1149, NotExpr target_6, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="predecode_packet"
		and target_1.getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getQualifier().(VariableAccess).getLocation())
}

predicate func_2(Variable vstream_1149, NotExpr target_5) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="last_packet"
		and target_2.getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vstream_1149, Variable vpkt_desc_1151, NotExpr target_6, ExprStmt target_9) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="last_packet"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_3.getRValue().(VariableAccess).getTarget()=vpkt_desc_1151
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_3.getRValue().(VariableAccess).getLocation()))
}

predicate func_4(Variable vstream_1149, Variable vpkt_desc_1151, NotExpr target_6) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="premux_packet"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpkt_desc_1151
		and target_4.getParent().(IfStmt).getCondition()=target_6)
}

predicate func_5(Variable vstream_1149, ExprStmt target_22, NotExpr target_5) {
		target_5.getOperand().(PointerFieldAccess).getTarget().getName()="premux_packet"
		and target_5.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_5.getParent().(IfStmt).getThen()=target_22
}

predicate func_6(Variable vstream_1149, ExprStmt target_9, NotExpr target_6) {
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="predecode_packet"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_6.getParent().(IfStmt).getThen()=target_9
}

predicate func_7(Variable vstream_1149, PointerFieldAccess target_7) {
		target_7.getTarget().getName()="premux_packet"
		and target_7.getQualifier().(VariableAccess).getTarget()=vstream_1149
}

predicate func_8(Variable vpkt_desc_1151, AssignExpr target_8) {
		target_8.getLValue().(VariableAccess).getTarget()=vpkt_desc_1151
		and target_8.getRValue().(FunctionCall).getTarget().hasName("av_mallocz")
		and target_8.getRValue().(FunctionCall).getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_8.getRValue().(FunctionCall).getArgument(0).(SizeofTypeOperator).getValue()="32"
		and target_8.getParent().(AssignExpr).getRValue() = target_8
		and target_8.getParent().(AssignExpr).getLValue() instanceof PointerDereferenceExpr
}

predicate func_9(Variable vstream_1149, Variable vpkt_desc_1151, NotExpr target_6, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="predecode_packet"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_9.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vpkt_desc_1151
		and target_9.getParent().(IfStmt).getCondition()=target_6
}

predicate func_10(Variable vstream_1149, VariableAccess target_10) {
		target_10.getTarget()=vstream_1149
}

predicate func_11(Variable vstream_1149, VariableAccess target_11) {
		target_11.getTarget()=vstream_1149
}

predicate func_12(Variable vpkt_desc_1151, VariableAccess target_12) {
		target_12.getTarget()=vpkt_desc_1151
}

predicate func_13(Variable vstream_1149, AssignExpr target_13) {
		target_13.getLValue().(PointerFieldAccess).getTarget().getName()="next_packet"
		and target_13.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_13.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="premux_packet"
		and target_13.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
}

predicate func_14(Variable vstream_1149, PointerDereferenceExpr target_14) {
		target_14.getOperand().(PointerFieldAccess).getTarget().getName()="next_packet"
		and target_14.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_14.getParent().(AssignExpr).getLValue() = target_14
		and target_14.getParent().(AssignExpr).getRValue() instanceof AssignExpr
}

predicate func_15(Variable vstream_1149, Variable vpkt_desc_1151, AssignExpr target_15) {
		target_15.getLValue().(PointerFieldAccess).getTarget().getName()="next_packet"
		and target_15.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_1149
		and target_15.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="next"
		and target_15.getRValue().(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpkt_desc_1151
}

predicate func_22(ExprStmt target_22) {
		target_22.getExpr() instanceof AssignExpr
}

from Function func, Variable vstream_1149, Variable vpkt_desc_1151, PointerFieldAccess target_0, PointerFieldAccess target_1, NotExpr target_5, NotExpr target_6, PointerFieldAccess target_7, AssignExpr target_8, ExprStmt target_9, VariableAccess target_10, VariableAccess target_11, VariableAccess target_12, AssignExpr target_13, PointerDereferenceExpr target_14, AssignExpr target_15, ExprStmt target_22
where
func_0(vstream_1149, target_9, target_0)
and func_1(vstream_1149, target_6, target_1)
and not func_2(vstream_1149, target_5)
and not func_3(vstream_1149, vpkt_desc_1151, target_6, target_9)
and not func_4(vstream_1149, vpkt_desc_1151, target_6)
and func_5(vstream_1149, target_22, target_5)
and func_6(vstream_1149, target_9, target_6)
and func_7(vstream_1149, target_7)
and func_8(vpkt_desc_1151, target_8)
and func_9(vstream_1149, vpkt_desc_1151, target_6, target_9)
and func_10(vstream_1149, target_10)
and func_11(vstream_1149, target_11)
and func_12(vpkt_desc_1151, target_12)
and func_13(vstream_1149, target_13)
and func_14(vstream_1149, target_14)
and func_15(vstream_1149, vpkt_desc_1151, target_15)
and func_22(target_22)
and vstream_1149.getType().hasName("StreamInfo *")
and vpkt_desc_1151.getType().hasName("PacketDesc *")
and vstream_1149.getParentScope+() = func
and vpkt_desc_1151.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
