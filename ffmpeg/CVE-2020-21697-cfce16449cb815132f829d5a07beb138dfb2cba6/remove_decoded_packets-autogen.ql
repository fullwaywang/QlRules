/**
 * @name ffmpeg-cfce16449cb815132f829d5a07beb138dfb2cba6-remove_decoded_packets
 * @id cpp/ffmpeg/cfce16449cb815132f829d5a07beb138dfb2cba6/remove-decoded-packets
 * @description ffmpeg-cfce16449cb815132f829d5a07beb138dfb2cba6-libavformat/mpegenc.c-remove_decoded_packets CVE-2020-21697
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vstream_975, ExprStmt target_1) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="predecode_packet"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_975
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="last_packet"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_975
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vstream_975, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="predecode_packet"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstream_975
		and target_1.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="next"
}

from Function func, Variable vstream_975, ExprStmt target_1
where
not func_0(vstream_975, target_1)
and func_1(vstream_975, target_1)
and vstream_975.getType().hasName("StreamInfo *")
and vstream_975.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
