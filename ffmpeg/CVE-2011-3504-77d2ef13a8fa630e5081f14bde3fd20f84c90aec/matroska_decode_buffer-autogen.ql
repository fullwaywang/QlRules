/**
 * @name ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-matroska_decode_buffer
 * @id cpp/ffmpeg/77d2ef13a8fa630e5081f14bde3fd20f84c90aec/matroska-decode-buffer
 * @description ffmpeg-77d2ef13a8fa630e5081f14bde3fd20f84c90aec-libavformat/matroskadec.c-matroska_decode_buffer CVE-2011-3504
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpkt_data_937, VariableAccess target_0) {
		target_0.getTarget()=vpkt_data_937
		and target_0.getParent().(AssignExpr).getLValue() = target_0
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkt_data_937
		and target_0.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_1(Variable vpkt_data_937, VariableAccess target_1) {
		target_1.getTarget()=vpkt_data_937
		and target_1.getParent().(AssignExpr).getLValue() = target_1
		and target_1.getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_1.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkt_data_937
		and target_1.getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_2(Variable vzstream_960, ExprStmt target_6, ExprStmt target_7) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("uint8_t *")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("inflateEnd")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vzstream_960
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vpkt_data_937, ExprStmt target_8, ExprStmt target_9) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpkt_data_937
		and target_3.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint8_t *")
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_4(Variable vbzstream_981, ExprStmt target_10, ExprStmt target_11) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(VariableAccess).getType().hasName("uint8_t *")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("BZ2_bzDecompressEnd")
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vbzstream_981
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation())
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vpkt_data_937, ExprStmt target_12, ExprStmt target_13) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpkt_data_937
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getType().hasName("uint8_t *")
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_13.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_6(Variable vzstream_960, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_in"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vzstream_960
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_7(Variable vzstream_960, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vzstream_960
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="total_out"
		and target_7.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vzstream_960
}

predicate func_8(Variable vpkt_data_937, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpkt_data_937
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkt_data_937
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_9(Variable vpkt_data_937, Variable vzstream_960, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="next_out"
		and target_9.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vzstream_960
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpkt_data_937
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="total_out"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vzstream_960
}

predicate func_10(Variable vbzstream_981, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_in"
		and target_10.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbzstream_981
		and target_10.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_11(Variable vbzstream_981, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="avail_out"
		and target_11.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbzstream_981
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getTarget().getName()="total_out_lo32"
		and target_11.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbzstream_981
}

predicate func_12(Variable vpkt_data_937, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpkt_data_937
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_realloc")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpkt_data_937
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_13(Variable vpkt_data_937, Variable vbzstream_981, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="next_out"
		and target_13.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbzstream_981
		and target_13.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vpkt_data_937
		and target_13.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="total_out_lo32"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbzstream_981
}

from Function func, Variable vpkt_data_937, Variable vzstream_960, Variable vbzstream_981, VariableAccess target_0, VariableAccess target_1, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13
where
func_0(vpkt_data_937, target_0)
and func_1(vpkt_data_937, target_1)
and not func_2(vzstream_960, target_6, target_7)
and not func_3(vpkt_data_937, target_8, target_9)
and not func_4(vbzstream_981, target_10, target_11)
and not func_5(vpkt_data_937, target_12, target_13)
and func_6(vzstream_960, target_6)
and func_7(vzstream_960, target_7)
and func_8(vpkt_data_937, target_8)
and func_9(vpkt_data_937, vzstream_960, target_9)
and func_10(vbzstream_981, target_10)
and func_11(vbzstream_981, target_11)
and func_12(vpkt_data_937, target_12)
and func_13(vpkt_data_937, vbzstream_981, target_13)
and vpkt_data_937.getType().hasName("uint8_t *")
and vzstream_960.getType().hasName("z_stream")
and vbzstream_981.getType().hasName("bz_stream")
and vpkt_data_937.(LocalVariable).getFunction() = func
and vzstream_960.(LocalVariable).getFunction() = func
and vbzstream_981.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
