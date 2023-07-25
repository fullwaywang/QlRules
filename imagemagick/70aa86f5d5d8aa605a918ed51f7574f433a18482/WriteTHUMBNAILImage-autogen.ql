/**
 * @name imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-WriteTHUMBNAILImage
 * @id cpp/imagemagick/70aa86f5d5d8aa605a918ed51f7574f433a18482/WriteTHUMBNAILImage
 * @description imagemagick-70aa86f5d5d8aa605a918ed51f7574f433a18482-coders/thumbnail.c-WriteTHUMBNAILImage CVE-2021-20311
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vprofile_159, Variable vlength_174, Variable vq_180, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vq_180
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoDatum")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoLength")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlength_174
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoDatum")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoLength")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getLeftOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vq_180
		and target_0.getParent().(IfStmt).getThen()=target_5
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

/*predicate func_1(Variable vprofile_159, RelationalOperation target_9) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("GetStringInfoDatum")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getArgument(0).(VariableAccess).getLocation()))
}

*/
/*predicate func_2(Variable vprofile_159, RelationalOperation target_6) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("GetStringInfoLength")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_2.getArgument(0).(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

*/
predicate func_3(Variable vq_180, VariableAccess target_3) {
		target_3.getTarget()=vq_180
}

predicate func_4(Variable vlength_174, VariableAccess target_4) {
		target_4.getTarget()=vlength_174
}

predicate func_5(BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImageDoesNotHaveAThumbnail"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImageDoesNotHaveAThumbnail"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
}

predicate func_6(Variable vprofile_159, Variable vlength_174, Variable vq_180, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vq_180
		and target_6.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlength_174
		and target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoDatum")
		and target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getTarget().hasName("GetStringInfoLength")
		and target_6.getLesserOperand().(PointerArithmeticOperation).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
}

predicate func_7(Variable vlength_174, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vlength_174
		and target_7.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("StringToLong")
}

predicate func_8(Variable vlength_174, Variable vq_180, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BlobToImage")
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vq_180
		and target_8.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlength_174
}

predicate func_9(Variable vprofile_159, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("GetStringInfoLength")
		and target_9.getGreaterOperand().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprofile_159
		and target_9.getGreaterOperand().(SubExpr).getRightOperand().(Literal).getValue()="3"
}

from Function func, Variable vprofile_159, Variable vlength_174, Variable vq_180, VariableAccess target_3, VariableAccess target_4, BlockStmt target_5, RelationalOperation target_6, ExprStmt target_7, ExprStmt target_8, RelationalOperation target_9
where
not func_0(vprofile_159, vlength_174, vq_180, target_5, target_6, target_7, target_8)
and func_3(vq_180, target_3)
and func_4(vlength_174, target_4)
and func_5(target_5)
and func_6(vprofile_159, vlength_174, vq_180, target_6)
and func_7(vlength_174, target_7)
and func_8(vlength_174, vq_180, target_8)
and func_9(vprofile_159, target_9)
and vprofile_159.getType().hasName("const StringInfo *")
and vlength_174.getType().hasName("size_t")
and vq_180.getType().hasName("unsigned char *")
and vprofile_159.getParentScope+() = func
and vlength_174.getParentScope+() = func
and vq_180.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
