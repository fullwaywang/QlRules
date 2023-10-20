/**
 * @name ffmpeg-5a396bb3a66a61a68b80f2369d0249729bf85e04-avpriv_dv_produce_packet
 * @id cpp/ffmpeg/5a396bb3a66a61a68b80f2369d0249729bf85e04/avpriv-dv-produce-packet
 * @description ffmpeg-5a396bb3a66a61a68b80f2369d0249729bf85e04-libavformat/dv.c-avpriv_dv_produce_packet CVE-2011-3929
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vc_326, ExprStmt target_2, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="ach"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_326
		and target_0.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0)
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbuf_327, Variable vppcm_330, Parameter vc_326, Function func, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("dv_extract_audio")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vbuf_327
		and target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vppcm_330
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="sys"
		and target_1.getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_326
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Variable vppcm_330, Parameter vc_326, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vppcm_330
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="audio_buf"
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_326
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
}

from Function func, Parameter vbuf_327, Variable vppcm_330, Parameter vc_326, ExprStmt target_1, ExprStmt target_2
where
not func_0(vc_326, target_2, target_1, func)
and func_1(vbuf_327, vppcm_330, vc_326, func, target_1)
and func_2(vppcm_330, vc_326, target_2)
and vbuf_327.getType().hasName("uint8_t *")
and vppcm_330.getType().hasName("uint8_t *[4]")
and vc_326.getType().hasName("DVDemuxContext *")
and vbuf_327.getFunction() = func
and vppcm_330.(LocalVariable).getFunction() = func
and vc_326.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
