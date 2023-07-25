/**
 * @name ffmpeg-e1c0cfaa419aa5d320540d5a1b3f8fd9b82ab7e5-tiff_decode_tag
 * @id cpp/ffmpeg/e1c0cfaa419aa5d320540d5a1b3f8fd9b82ab7e5/tiff-decode-tag
 * @description ffmpeg-e1c0cfaa419aa5d320540d5a1b3f8fd9b82ab7e5-libavcodec/tiff.c-tiff_decode_tag CVE-2014-8544
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_777, Variable vvalue_777, Parameter vs_775, RelationalOperation target_3, ExprStmt target_2, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_0.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_0.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="This format is not supported (bpp=%d, %d components)\n"
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vvalue_777
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcount_777
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
		and target_0.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_775, VariableAccess target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vcount_777, Parameter vs_775, RelationalOperation target_3, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_2.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="This format is not supported (bpp=%d, %d components)\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="bpp"
		and target_2.getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_2.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vcount_777
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
}

predicate func_3(Variable vcount_777, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vcount_777
		and target_3.getLesserOperand().(Literal).getValue()="4"
}

predicate func_4(Variable vvalue_777, Parameter vs_775, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="height"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_4.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_777
}

predicate func_5(Variable vvalue_777, Parameter vs_775, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vvalue_777
}

predicate func_6(Variable vcount_777, Parameter vs_775, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bppcount"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_6.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcount_777
}

predicate func_7(Variable vtag_777, VariableAccess target_7) {
		target_7.getTarget()=vtag_777
}

predicate func_8(Parameter vs_775, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bpp"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_8.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="4294967295"
}

predicate func_9(Parameter vs_775, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="avctx"
		and target_9.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_775
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="16"
		and target_9.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Samples per pixel requires a single value, many provided\n"
}

from Function func, Variable vtag_777, Variable vcount_777, Variable vvalue_777, Parameter vs_775, ExprStmt target_2, RelationalOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, VariableAccess target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vcount_777, vvalue_777, vs_775, target_3, target_2, target_4, target_5, target_6)
and not func_1(vs_775, target_7, target_8, target_9)
and func_2(vcount_777, vs_775, target_3, target_2)
and func_3(vcount_777, target_3)
and func_4(vvalue_777, vs_775, target_4)
and func_5(vvalue_777, vs_775, target_5)
and func_6(vcount_777, vs_775, target_6)
and func_7(vtag_777, target_7)
and func_8(vs_775, target_8)
and func_9(vs_775, target_9)
and vtag_777.getType().hasName("unsigned int")
and vcount_777.getType().hasName("unsigned int")
and vvalue_777.getType().hasName("unsigned int")
and vs_775.getType().hasName("TiffContext *")
and vtag_777.(LocalVariable).getFunction() = func
and vcount_777.(LocalVariable).getFunction() = func
and vvalue_777.(LocalVariable).getFunction() = func
and vs_775.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
