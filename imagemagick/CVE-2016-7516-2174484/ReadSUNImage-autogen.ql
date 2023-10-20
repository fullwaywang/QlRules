/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-ReadSUNImage
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/ReadSUNImage
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-coders/sun.c-ReadSUNImage CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbytes_per_line_257, Variable vimage_235, MulExpr target_3, ExprStmt target_4, EqualityOperation target_5) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_235
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_0.getThen().(PointerFieldAccess).getTarget().getName()="columns"
		and target_0.getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_235
		and target_0.getElse().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getLeftOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vbytes_per_line_257, Variable vheight_259, Variable vsun_pixels_270, Variable vimage_235, MulExpr target_3, MulExpr target_6, ExprStmt target_7, EqualityOperation target_8, EqualityOperation target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("ResetMagickMemory")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsun_pixels_270
		and target_1.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vheight_259
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getTarget().getName()="columns"
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_235
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getElse().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_3.getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_6.getLeftOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_8.getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_1.getExpr().(FunctionCall).getArgument(2).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(ConditionalExpr).getThen().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vbytes_per_line_257, VariableAccess target_2) {
		target_2.getTarget()=vbytes_per_line_257
}

predicate func_3(Variable vbytes_per_line_257, MulExpr target_3) {
		target_3.getLeftOperand().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_3.getRightOperand().(SizeofExprOperator).getValue()="1"
}

predicate func_4(Variable vimage_235, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_235
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_235
}

predicate func_5(Variable vimage_235, EqualityOperation target_5) {
		target_5.getAnOperand().(VariableAccess).getTarget()=vimage_235
		and target_5.getAnOperand().(Literal).getValue()="0"
}

predicate func_6(Variable vbytes_per_line_257, Variable vheight_259, MulExpr target_6) {
		target_6.getLeftOperand().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_6.getRightOperand().(VariableAccess).getTarget()=vheight_259
}

predicate func_7(Variable vbytes_per_line_257, Variable vheight_259, Variable vsun_pixels_270, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsun_pixels_270
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vheight_259
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vbytes_per_line_257
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
}

predicate func_8(Variable vsun_pixels_270, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vsun_pixels_270
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vimage_235, EqualityOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vimage_235
		and target_9.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vbytes_per_line_257, Variable vheight_259, Variable vsun_pixels_270, Variable vimage_235, VariableAccess target_2, MulExpr target_3, ExprStmt target_4, EqualityOperation target_5, MulExpr target_6, ExprStmt target_7, EqualityOperation target_8, EqualityOperation target_9
where
not func_0(vbytes_per_line_257, vimage_235, target_3, target_4, target_5)
and not func_1(vbytes_per_line_257, vheight_259, vsun_pixels_270, vimage_235, target_3, target_6, target_7, target_8, target_9)
and func_2(vbytes_per_line_257, target_2)
and func_3(vbytes_per_line_257, target_3)
and func_4(vimage_235, target_4)
and func_5(vimage_235, target_5)
and func_6(vbytes_per_line_257, vheight_259, target_6)
and func_7(vbytes_per_line_257, vheight_259, vsun_pixels_270, target_7)
and func_8(vsun_pixels_270, target_8)
and func_9(vimage_235, target_9)
and vbytes_per_line_257.getType().hasName("size_t")
and vheight_259.getType().hasName("size_t")
and vsun_pixels_270.getType().hasName("unsigned char *")
and vimage_235.getType().hasName("Image *")
and vbytes_per_line_257.getParentScope+() = func
and vheight_259.getParentScope+() = func
and vsun_pixels_270.getParentScope+() = func
and vimage_235.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
