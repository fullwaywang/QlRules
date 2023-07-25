/**
 * @name imagemagick-ecb31dbad39ccdc65868d5d2a37f0f0521250832-ReadBMPImage
 * @id cpp/imagemagick/ecb31dbad39ccdc65868d5d2a37f0f0521250832/ReadBMPImage
 * @description imagemagick-ecb31dbad39ccdc65868d5d2a37f0f0521250832-coders/bmp.c-ReadBMPImage CVE-2018-16645
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_510, Variable vbmp_info_513, Variable vimage_516, Parameter vimage_info_510, Variable v__func__, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="number_colors"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbmp_info_513
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("GetBlobSize")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_510
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="InsufficientImageDataInFile"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_510
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_516
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_516
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(11)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_2(Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Variable vbmp_info_513, EqualityOperation target_3) {
		target_3.getAnOperand().(ValueFieldAccess).getTarget().getName()="size"
		and target_3.getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbmp_info_513
		and target_3.getAnOperand().(Literal).getValue()="12"
}

predicate func_4(Parameter vexception_510, Parameter vimage_info_510, Variable v__func__, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_510
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="NonOS2HeaderSizeError"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="NonOS2HeaderSizeError"
		and target_4.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_510
}

predicate func_5(Parameter vexception_510, Variable vimage_516, Variable v__func__, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_510
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="LengthAndFilesizeDoNotMatch"
		and target_5.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_516
}

predicate func_6(Variable vbmp_info_513, Variable vimage_516, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="number_colors"
		and target_6.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbmp_info_513
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlobLSBLong")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
}

predicate func_7(Variable vbmp_info_513, Variable vimage_516, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="colors_important"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vbmp_info_513
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlobLSBLong")
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
}

predicate func_8(Parameter vexception_510, Parameter vimage_info_510, Variable v__func__, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_8.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_510
		and target_8.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_8.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_8.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="NegativeOrZeroImageSize"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_8.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="NegativeOrZeroImageSize"
		and target_8.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_8.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_510
}

predicate func_9(Variable v__func__, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("LogMagickEvent")
		and target_9.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_9.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_9.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_9.getExpr().(FunctionCall).getArgument(4).(StringLiteral).getValue()="  Format: MS Windows bitmap"
}

from Function func, Parameter vexception_510, Variable vbmp_info_513, Variable vimage_516, Parameter vimage_info_510, Variable v__func__, EmptyStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9
where
not func_0(vexception_510, vbmp_info_513, vimage_516, vimage_info_510, v__func__, target_3, target_4, target_5, target_6, target_7, target_8, target_9)
and func_2(func, target_2)
and func_3(vbmp_info_513, target_3)
and func_4(vexception_510, vimage_info_510, v__func__, target_4)
and func_5(vexception_510, vimage_516, v__func__, target_5)
and func_6(vbmp_info_513, vimage_516, target_6)
and func_7(vbmp_info_513, vimage_516, target_7)
and func_8(vexception_510, vimage_info_510, v__func__, target_8)
and func_9(v__func__, target_9)
and vexception_510.getType().hasName("ExceptionInfo *")
and vbmp_info_513.getType().hasName("BMPInfo")
and vimage_516.getType().hasName("Image *")
and vimage_info_510.getType().hasName("const ImageInfo *")
and v__func__.getType() instanceof ArrayType
and vexception_510.getParentScope+() = func
and vbmp_info_513.getParentScope+() = func
and vimage_516.getParentScope+() = func
and vimage_info_510.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
