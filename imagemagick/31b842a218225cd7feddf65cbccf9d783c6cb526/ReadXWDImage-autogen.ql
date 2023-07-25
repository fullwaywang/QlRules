/**
 * @name imagemagick-31b842a218225cd7feddf65cbccf9d783c6cb526-ReadXWDImage
 * @id cpp/imagemagick/31b842a218225cd7feddf65cbccf9d783c6cb526/ReadXWDImage
 * @description imagemagick-31b842a218225cd7feddf65cbccf9d783c6cb526-coders/xwd.c-ReadXWDImage CVE-2017-11166
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vexception_150, Variable vimage_159, Parameter vimage_info_150, Variable vlength_186, Variable v__func__, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_186
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="1152921504606846975"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_150
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_150
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_159
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_159
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_159
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_0.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_2(Function func, EmptyStmt target_2) {
		target_2.toString() = ";"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(EqualityOperation target_3) {
		target_3.getAnOperand().(ValueFieldAccess).getTarget().getName()="ncolors"
		and target_3.getAnOperand().(Literal).getValue()="0"
}

predicate func_4(Parameter vexception_150, Parameter vimage_info_150, Variable v__func__, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_150
		and target_4.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_4.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="UnexpectedEndOfFile"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_4.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="UnexpectedEndOfFile"
		and target_4.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_4.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_150
}

predicate func_5(Parameter vexception_150, Parameter vimage_info_150, Variable v__func__, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_150
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_5.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_5.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_5.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_5.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_150
}

predicate func_6(Variable vimage_159, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_159
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_6.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_159
}

predicate func_7(Variable vlength_186, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_186
		and target_7.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ncolors"
}

predicate func_8(Variable vlength_186, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireQuantumMemory")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vlength_186
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="16"
}

from Function func, Parameter vexception_150, Variable vimage_159, Parameter vimage_info_150, Variable vlength_186, Variable v__func__, EmptyStmt target_2, EqualityOperation target_3, ExprStmt target_4, ExprStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
not func_0(vexception_150, vimage_159, vimage_info_150, vlength_186, v__func__, target_3, target_4, target_5, target_6, target_7, target_8)
and func_2(func, target_2)
and func_3(target_3)
and func_4(vexception_150, vimage_info_150, v__func__, target_4)
and func_5(vexception_150, vimage_info_150, v__func__, target_5)
and func_6(vimage_159, target_6)
and func_7(vlength_186, target_7)
and func_8(vlength_186, target_8)
and vexception_150.getType().hasName("ExceptionInfo *")
and vimage_159.getType().hasName("Image *")
and vimage_info_150.getType().hasName("const ImageInfo *")
and vlength_186.getType().hasName("size_t")
and v__func__.getType() instanceof ArrayType
and vexception_150.getParentScope+() = func
and vimage_159.getParentScope+() = func
and vimage_info_150.getParentScope+() = func
and vlength_186.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
