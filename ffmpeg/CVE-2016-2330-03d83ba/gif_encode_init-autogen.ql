/**
 * @name ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-gif_encode_init
 * @id cpp/ffmpeg/03d83ba34b2070878909eae18dfac0f519503777/gif-encode-init
 * @description ffmpeg-03d83ba34b2070878909eae18dfac0f519503777-libavcodec/gif.c-gif_encode_init CVE-2016-2330
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_218, ExprStmt target_4, ExprStmt target_5) {
	exists(AssignExpr target_0 |
		target_0.getLValue().(PointerFieldAccess).getTarget().getName()="buf_size"
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and target_0.getRValue().(AddExpr).getAnOperand() instanceof MulExpr
		and target_0.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1000"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_218, ExprStmt target_6, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf_size"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vs_218, ExprStmt target_5, ExprStmt target_6) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="buf_size"
		and target_2.getQualifier().(VariableAccess).getTarget()=vs_218
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation())
		and target_2.getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Parameter vavctx_216, MulExpr target_3) {
		target_3.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_3.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_216
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="height"
		and target_3.getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_216
		and target_3.getRightOperand().(Literal).getValue()="2"
		and target_3.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
}

predicate func_4(Variable vs_218, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="lzw"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_mallocz")
}

predicate func_5(Variable vs_218, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0) instanceof MulExpr
}

predicate func_6(Variable vs_218, Parameter vavctx_216, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="tmpl"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_218
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="width"
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavctx_216
}

from Function func, Variable vs_218, Parameter vavctx_216, MulExpr target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6
where
not func_0(vs_218, target_4, target_5)
and not func_1(vs_218, target_6, func)
and func_3(vavctx_216, target_3)
and func_4(vs_218, target_4)
and func_5(vs_218, target_5)
and func_6(vs_218, vavctx_216, target_6)
and vs_218.getType().hasName("GIFContext *")
and vavctx_216.getType().hasName("AVCodecContext *")
and vs_218.getParentScope+() = func
and vavctx_216.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
