/**
 * @name imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-ReadRLEImage
 * @id cpp/imagemagick/2174484dfa68a594e2f9ad17f46217b6120db18d/ReadRLEImage
 * @description imagemagick-2174484dfa68a594e2f9ad17f46217b6120db18d-coders/rle.c-ReadRLEImage CVE-2016-7516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpixel_info_length_179, ExprStmt target_8, RelationalOperation target_9, VariableAccess target_0) {
		target_0.getTarget()=vpixel_info_length_179
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getLocation())
		and target_0.getLocation().isBefore(target_9.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_1(Parameter vimage_info_127, Parameter vexception_127, Variable vimage_140, Variable v__func__, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand() instanceof SizeofExprOperator
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vimage_140
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("CloseBlob")
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_140
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_140
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_1.getThen().(BlockStmt).getStmt(2).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_10.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_2(Parameter vimage_info_127, Parameter vexception_127, Variable v__func__, ExprStmt target_10, ExprStmt target_11) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("ThrowMagickException")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_2.getArgument(1) instanceof StringLiteral
		and target_2.getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_2.getArgument(3) instanceof Literal
		and target_2.getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_2.getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_2.getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_2.getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_2.getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_2.getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
		and target_10.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vimage_140, Variable vpixel_info_154, Variable vnumber_planes_filled_176, ExprStmt target_8, EqualityOperation target_13, EqualityOperation target_14) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_154
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="columns"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnumber_planes_filled_176
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(MulExpr).getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_14.getAnOperand().(VariableAccess).getLocation()))
}

/*predicate func_4(Variable vimage_140, ExprStmt target_8) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="columns"
		and target_4.getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_5(Variable vimage_140, Variable vnumber_planes_filled_176, Variable vpixel_info_length_179, EqualityOperation target_13, ExprStmt target_8) {
	exists(MulExpr target_5 |
		target_5.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_5.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_5.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnumber_planes_filled_176
		and target_5.getRightOperand().(SizeofExprOperator).getValue()="1"
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("AcquireVirtualMemory")
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpixel_info_length_179
		and target_5.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof SizeofExprOperator
		and target_5.getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getLocation().isBefore(target_5.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getLocation()))
}

*/
predicate func_7(Function func, SizeofExprOperator target_7) {
		target_7.getValue()="1"
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vimage_140, Variable vnumber_planes_filled_176, Variable vpixel_info_length_179, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpixel_info_length_179
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="columns"
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="rows"
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getLeftOperand().(MulExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_140
		and target_8.getExpr().(AssignExpr).getRValue().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vnumber_planes_filled_176
}

predicate func_9(Variable vpixel_info_length_179, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vpixel_info_length_179
}

predicate func_10(Parameter vimage_info_127, Parameter vexception_127, Variable v__func__, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_10.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_10.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_10.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_10.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_10.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_10.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_10.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_10.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_10.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_10.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
}

predicate func_11(Parameter vimage_info_127, Parameter vexception_127, Variable v__func__, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_11.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexception_127
		and target_11.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_11.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=v__func__
		and target_11.getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_11.getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="MemoryAllocationFailed"
		and target_11.getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
		and target_11.getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_info_127
}

predicate func_12(Variable vimage_140, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vimage_140
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("DestroyImageList")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_140
}

predicate func_13(Variable vimage_140, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vimage_140
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vpixel_info_154, EqualityOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vpixel_info_154
		and target_14.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vimage_info_127, Parameter vexception_127, Variable vimage_140, Variable vpixel_info_154, Variable vnumber_planes_filled_176, Variable vpixel_info_length_179, Variable v__func__, VariableAccess target_0, SizeofExprOperator target_7, ExprStmt target_8, RelationalOperation target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, EqualityOperation target_13, EqualityOperation target_14
where
func_0(vpixel_info_length_179, target_8, target_9, target_0)
and not func_1(vimage_info_127, vexception_127, vimage_140, v__func__, target_10, target_11, target_12)
and not func_3(vimage_140, vpixel_info_154, vnumber_planes_filled_176, target_8, target_13, target_14)
and func_7(func, target_7)
and func_8(vimage_140, vnumber_planes_filled_176, vpixel_info_length_179, target_8)
and func_9(vpixel_info_length_179, target_9)
and func_10(vimage_info_127, vexception_127, v__func__, target_10)
and func_11(vimage_info_127, vexception_127, v__func__, target_11)
and func_12(vimage_140, target_12)
and func_13(vimage_140, target_13)
and func_14(vpixel_info_154, target_14)
and vimage_info_127.getType().hasName("const ImageInfo *")
and vexception_127.getType().hasName("ExceptionInfo *")
and vimage_140.getType().hasName("Image *")
and vpixel_info_154.getType().hasName("MemoryInfo *")
and vnumber_planes_filled_176.getType().hasName("size_t")
and vpixel_info_length_179.getType().hasName("size_t")
and v__func__.getType() instanceof ArrayType
and vimage_info_127.getParentScope+() = func
and vexception_127.getParentScope+() = func
and vimage_140.getParentScope+() = func
and vpixel_info_154.getParentScope+() = func
and vnumber_planes_filled_176.getParentScope+() = func
and vpixel_info_length_179.getParentScope+() = func
and not v__func__.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
