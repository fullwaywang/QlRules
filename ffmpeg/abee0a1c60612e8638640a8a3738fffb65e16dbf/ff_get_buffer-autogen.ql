/**
 * @name ffmpeg-abee0a1c60612e8638640a8a3738fffb65e16dbf-ff_get_buffer
 * @id cpp/ffmpeg/abee0a1c60612e8638640a8a3738fffb65e16dbf/ff-get-buffer
 * @description ffmpeg-abee0a1c60612e8638640a8a3738fffb65e16dbf-libavcodec/utils.c-ff_get_buffer CVE-2015-8663
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vframe_888, RelationalOperation target_2, FunctionCall target_3) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_888
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vframe_888
		and target_0.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_3.getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vavctx_888, RelationalOperation target_2, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vavctx_888
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_1.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="get_buffer() failed\n"
		and target_1.getParent().(IfStmt).getCondition()=target_2
}

predicate func_2(RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vavctx_888, Parameter vframe_888, FunctionCall target_3) {
		target_3.getTarget().hasName("get_buffer_internal")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vavctx_888
		and target_3.getArgument(1).(VariableAccess).getTarget()=vframe_888
}

from Function func, Parameter vavctx_888, Parameter vframe_888, ExprStmt target_1, RelationalOperation target_2, FunctionCall target_3
where
not func_0(vframe_888, target_2, target_3)
and func_1(vavctx_888, target_2, target_1)
and func_2(target_2)
and func_3(vavctx_888, vframe_888, target_3)
and vavctx_888.getType().hasName("AVCodecContext *")
and vframe_888.getType().hasName("AVFrame *")
and vavctx_888.getParentScope+() = func
and vframe_888.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
