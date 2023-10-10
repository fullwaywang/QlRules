/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-ReadVIFFImage
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/ReadVIFFImage
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-coders/viff.c-ReadVIFFImage CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vimage_info_140, Parameter vexception_141, Variable vimage_215, Variable vbytes_per_pixel_239, Variable vviff_info_254, Variable v__func__, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, MulExpr target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="map_rows"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="map_rows"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_pixel_239
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_215
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_7.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vimage_info_140, Parameter vexception_141, Variable v__func__, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_3.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_3.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_3.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_3.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_3.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_3.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
}

predicate func_4(Parameter vimage_info_140, Parameter vexception_141, Variable v__func__, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_141
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_4.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_140
}

predicate func_5(Variable vimage_215, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_215
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_215
}

predicate func_6(Variable vbytes_per_pixel_239, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbytes_per_pixel_239
		and target_6.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
}

predicate func_7(Variable vbytes_per_pixel_239, Variable vviff_info_254, MulExpr target_7) {
		target_7.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="map_rows"
		and target_7.getLeftOperand().(MulExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
		and target_7.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vbytes_per_pixel_239
		and target_7.getRightOperand().(SizeofExprOperator).getValue()="1"
}

predicate func_8(Variable vimage_215, Variable vviff_info_254, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="colors"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_215
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="map_columns"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vviff_info_254
}

from Function func, Parameter vimage_info_140, Parameter vexception_141, Variable vimage_215, Variable vbytes_per_pixel_239, Variable vviff_info_254, Variable v__func__, EmptyStmt target_2, ExprStmt target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, MulExpr target_7, ExprStmt target_8
where
not func_0(vimage_info_140, vexception_141, vimage_215, vbytes_per_pixel_239, vviff_info_254, v__func__, target_3, target_4, target_5, target_6, target_7, target_8)
and func_2(func, target_2)
and func_3(vimage_info_140, vexception_141, v__func__, target_3)
and func_4(vimage_info_140, vexception_141, v__func__, target_4)
and func_5(vimage_215, target_5)
and func_6(vbytes_per_pixel_239, target_6)
and func_7(vbytes_per_pixel_239, vviff_info_254, target_7)
and func_8(vimage_215, vviff_info_254, target_8)
and vimage_info_140.getType().hasName("const ImageInfo *")
and vexception_141.getType().hasName("ExceptionInfo *")
and vimage_215.getType().hasName("Image *")
and vbytes_per_pixel_239.getType().hasName("size_t")
and vviff_info_254.getType().hasName("ViffInfo")
and v__func__.getType() instanceof ArrayType
and vimage_info_140.getParentScope+() = func
and vexception_141.getParentScope+() = func
and vimage_215.getParentScope+() = func
and vbytes_per_pixel_239.getParentScope+() = func
and vviff_info_254.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
