/**
 * @name imagemagick-db0add932fb850d762b02604ca3053b7d7ab6deb-ReadBMPImage
 * @id cpp/imagemagick/db0add932fb850d762b02604ca3053b7d7ab6deb/ReadBMPImage
 * @description imagemagick-db0add932fb850d762b02604ca3053b7d7ab6deb-coders/bmp.c-ReadBMPImage CVE-2018-20467
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vimage_516, Variable voffset_522, BlockStmt target_11, ExprStmt target_12) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_522
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("TellBlob")
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("SeekBlob")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=voffset_522
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=voffset_522
		and target_0.getParent().(IfStmt).getThen()=target_11
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vimage_516, EqualityOperation target_13) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("TellBlob")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_13.getAnOperand().(VariableAccess).getLocation()))
}

*/
predicate func_5(Variable vbmp_info_513, ValueFieldAccess target_5) {
		target_5.getTarget().getName()="ba_offset"
		and target_5.getQualifier().(VariableAccess).getTarget()=vbmp_info_513
}

predicate func_6(Variable vimage_516, VariableAccess target_6) {
		target_6.getTarget()=vimage_516
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SeekBlob")
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_6.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_7(Variable voffset_522, BlockStmt target_11, VariableAccess target_7) {
		target_7.getTarget()=voffset_522
		and target_7.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_7.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_11
}

predicate func_8(EqualityOperation target_14, Function func, EmptyStmt target_8) {
		target_8.toString() = ";"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vbmp_info_513, EqualityOperation target_14, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="ba_offset"
		and target_9.getQualifier().(VariableAccess).getTarget()=vbmp_info_513
}

predicate func_11(BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_11.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
}

predicate func_12(Variable vimage_516, Variable voffset_522, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_522
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("SeekBlob")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vimage_516
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof ValueFieldAccess
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
}

predicate func_13(Variable vimage_516, EqualityOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vimage_516
		and target_13.getAnOperand().(Literal).getValue()="0"
}

predicate func_14(EqualityOperation target_14) {
		target_14.getAnOperand() instanceof ValueFieldAccess
		and target_14.getAnOperand().(Literal).getValue()="0"
}

from Function func, Variable vbmp_info_513, Variable vimage_516, Variable voffset_522, ValueFieldAccess target_5, VariableAccess target_6, VariableAccess target_7, EmptyStmt target_8, ValueFieldAccess target_9, BlockStmt target_11, ExprStmt target_12, EqualityOperation target_13, EqualityOperation target_14
where
not func_0(vimage_516, voffset_522, target_11, target_12)
and func_5(vbmp_info_513, target_5)
and func_6(vimage_516, target_6)
and func_7(voffset_522, target_11, target_7)
and func_8(target_14, func, target_8)
and func_9(vbmp_info_513, target_14, target_9)
and func_11(target_11)
and func_12(vimage_516, voffset_522, target_12)
and func_13(vimage_516, target_13)
and func_14(target_14)
and vbmp_info_513.getType().hasName("BMPInfo")
and vimage_516.getType().hasName("Image *")
and voffset_522.getType().hasName("MagickOffsetType")
and vbmp_info_513.getParentScope+() = func
and vimage_516.getParentScope+() = func
and voffset_522.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
