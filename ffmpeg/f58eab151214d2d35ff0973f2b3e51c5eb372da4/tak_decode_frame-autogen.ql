/**
 * @name ffmpeg-f58eab151214d2d35ff0973f2b3e51c5eb372da4-tak_decode_frame
 * @id cpp/ffmpeg/f58eab151214d2d35ff0973f2b3e51c5eb372da4/tak-decode-frame
 * @description ffmpeg-f58eab151214d2d35ff0973f2b3e51c5eb372da4-libavcodec/takdec.c-tak_decode_frame CVE-2014-2097
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_674, Parameter vavctx_671, EqualityOperation target_3, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_671
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="bps"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ti"
		and target_0.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_674
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_1(Variable vret_678, Parameter vavctx_671, EqualityOperation target_3, IfStmt target_1) {
		target_1.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_678
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("set_bps_params")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_671
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=vret_678
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_2(Variable vs_674, Parameter vavctx_671, Function func, IfStmt target_2) {
		target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="bps"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ti"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_674
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_2.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_671
		and target_2.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getThen().(BlockStmt).getStmt(1) instanceof IfStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Parameter vavctx_671, EqualityOperation target_3) {
		target_3.getAnOperand() instanceof ValueFieldAccess
		and target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="bits_per_raw_sample"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_671
}

from Function func, Variable vs_674, Variable vret_678, Parameter vavctx_671, ExprStmt target_0, IfStmt target_1, IfStmt target_2, EqualityOperation target_3
where
func_0(vs_674, vavctx_671, target_3, target_0)
and func_1(vret_678, vavctx_671, target_3, target_1)
and func_2(vs_674, vavctx_671, func, target_2)
and func_3(vavctx_671, target_3)
and vs_674.getType().hasName("TAKDecContext *")
and vret_678.getType().hasName("int")
and vavctx_671.getType().hasName("AVCodecContext *")
and vs_674.(LocalVariable).getFunction() = func
and vret_678.(LocalVariable).getFunction() = func
and vavctx_671.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
