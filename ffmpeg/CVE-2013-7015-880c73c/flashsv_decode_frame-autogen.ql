/**
 * @name ffmpeg-880c73cd76109697447fbfbaa8e5ee5683309446-flashsv_decode_frame
 * @id cpp/ffmpeg/880c73cd76109697447fbfbaa8e5ee5683309446/flashsv-decode-frame
 * @description ffmpeg-880c73cd76109697447fbfbaa8e5ee5683309446-libavcodec/flashsv.c-flashsv_decode_frame CVE-2013-7015
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vavctx_241, Variable vs_245, Variable vcur_blk_height_347, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="diff_start"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="diff_height"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcur_blk_height_347
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_241
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Block parameters invalid\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vhas_diff_353, VariableAccess target_1) {
		target_1.getTarget()=vhas_diff_353
}

predicate func_2(Parameter vavctx_241, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_241
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="inter frame without keyframe\n"
}

predicate func_3(Parameter vavctx_241, Variable vs_245, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_241
		and target_3.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="48"
		and target_3.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%dx%d diff start %d height %d\n"
		and target_3.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget().getType().hasName("int")
		and target_3.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="diff_start"
		and target_3.getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
		and target_3.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getTarget().getName()="diff_height"
		and target_3.getExpr().(FunctionCall).getArgument(6).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
}

predicate func_4(Variable vs_245, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="diff_height"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_bits")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget().getType().hasName("GetBitContext")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="8"
}

predicate func_5(Variable vs_245, Variable vcur_blk_height_347, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="diff_height"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_245
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcur_blk_height_347
}

predicate func_6(Variable vcur_blk_height_347, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getGreaterOperand().(VariableAccess).getTarget()=vcur_blk_height_347
}

from Function func, Parameter vavctx_241, Variable vs_245, Variable vcur_blk_height_347, Variable vhas_diff_353, VariableAccess target_1, ExprStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, RelationalOperation target_6
where
not func_0(vavctx_241, vs_245, vcur_blk_height_347, target_1, target_2, target_3, target_4, target_5, target_6)
and func_1(vhas_diff_353, target_1)
and func_2(vavctx_241, target_2)
and func_3(vavctx_241, vs_245, target_3)
and func_4(vs_245, target_4)
and func_5(vs_245, vcur_blk_height_347, target_5)
and func_6(vcur_blk_height_347, target_6)
and vavctx_241.getType().hasName("AVCodecContext *")
and vs_245.getType().hasName("FlashSVContext *")
and vcur_blk_height_347.getType().hasName("int")
and vhas_diff_353.getType().hasName("int")
and vavctx_241.getFunction() = func
and vs_245.(LocalVariable).getFunction() = func
and vcur_blk_height_347.(LocalVariable).getFunction() = func
and vhas_diff_353.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
