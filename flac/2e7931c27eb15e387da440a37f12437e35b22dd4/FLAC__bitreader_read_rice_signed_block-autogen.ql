/**
 * @name flac-2e7931c27eb15e387da440a37f12437e35b22dd4-FLAC__bitreader_read_rice_signed_block
 * @id cpp/flac/2e7931c27eb15e387da440a37f12437e35b22dd4/FLAC--bitreader-read-rice-signed-block
 * @description flac-2e7931c27eb15e387da440a37f12437e35b22dd4-src/libFLAC/bitreader.c-FLAC__bitreader_read_rice_signed_block CVE-2020-0499
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vbr_749, Variable vcwords_754, ExprStmt target_2, ExprStmt target_4) {
	exists(ConditionalExpr target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vcwords_754
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="capacity"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbr_749
		and target_0.getThen() instanceof BinaryBitwiseOperation
		and target_0.getElse().(Literal).getValue()="0"
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vbr_749, Variable vcwords_754, BinaryBitwiseOperation target_1) {
		target_1.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="buffer"
		and target_1.getLeftOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbr_749
		and target_1.getLeftOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vcwords_754
		and target_1.getRightOperand().(PointerFieldAccess).getTarget().getName()="consumed_bits"
		and target_1.getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbr_749
		and target_1.getParent().(AssignExpr).getRValue() = target_1
}

predicate func_2(Parameter vbr_749, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(Literal).getValue()="32"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getTarget().getName()="consumed_bits"
		and target_2.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbr_749
}

predicate func_4(Parameter vbr_749, Variable vcwords_754, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcwords_754
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="consumed_words"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vbr_749
}

from Function func, Parameter vbr_749, Variable vcwords_754, BinaryBitwiseOperation target_1, ExprStmt target_2, ExprStmt target_4
where
not func_0(vbr_749, vcwords_754, target_2, target_4)
and func_1(vbr_749, vcwords_754, target_1)
and func_2(vbr_749, target_2)
and func_4(vbr_749, vcwords_754, target_4)
and vbr_749.getType().hasName("FLAC__BitReader *")
and vcwords_754.getType().hasName("uint32_t")
and vbr_749.getParentScope+() = func
and vcwords_754.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
