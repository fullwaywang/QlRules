/**
 * @name imagemagick-4b1b9c0522628887195bad3a6723f7000b0c9a58-ReadPSDImage
 * @id cpp/imagemagick/4b1b9c0522628887195bad3a6723f7000b0c9a58/ReadPSDImage
 * @description imagemagick-4b1b9c0522628887195bad3a6723f7000b0c9a58-coders/psd.c-ReadPSDImage CVE-2016-7522
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1770, BlockStmt target_2, ExprStmt target_3) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1770
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getParent().(LogicalOrExpr).getAnOperand() instanceof EqualityOperation
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("LocaleNCompare")
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="8BIM"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_0.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlength_1770, Variable vcount_1782, BlockStmt target_2, EqualityOperation target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vcount_1782
		and target_1.getAnOperand().(VariableAccess).getTarget()=vlength_1770
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("LocaleNCompare")
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="8BIM"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_2
}

predicate func_2(BlockStmt target_2) {
		target_2.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("RelinquishMagickMemory")
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ThrowMagickException")
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof Literal
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(StringLiteral).getValue()="ImproperImageHeader"
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getThen().(StringLiteral).getValue()="unknown"
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5).(ConditionalExpr).getElse().(StringLiteral).getValue()="ImproperImageHeader"
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(6).(StringLiteral).getValue()="`%s'"
		and target_2.getStmt(1).(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(7).(PointerFieldAccess).getTarget().getName()="filename"
}

predicate func_3(Variable vlength_1770, Variable vcount_1782, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcount_1782
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadBlob")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlength_1770
}

from Function func, Variable vlength_1770, Variable vcount_1782, EqualityOperation target_1, BlockStmt target_2, ExprStmt target_3
where
not func_0(vlength_1770, target_2, target_3)
and func_1(vlength_1770, vcount_1782, target_2, target_1)
and func_2(target_2)
and func_3(vlength_1770, vcount_1782, target_3)
and vlength_1770.getType().hasName("MagickSizeType")
and vcount_1782.getType().hasName("ssize_t")
and vlength_1770.getParentScope+() = func
and vcount_1782.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
