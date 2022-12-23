/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_init_bitrate_mask
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7915-init-bitrate-mask
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7915_init_bitrate_mask CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmvif_171, Variable vi_172) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="gi"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="control"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bitrate_mask"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvif_171
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_172)
}

predicate func_1(Variable vmvif_171, Variable vi_172) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="he_gi"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="control"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bitrate_mask"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvif_171
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_172
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="255"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getValue()="255"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(Literal).getValue()="64"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_1.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="7")
}

predicate func_2(Variable vmvif_171, Variable vi_172) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="he_ltf"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="control"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="bitrate_mask"
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmvif_171
		and target_2.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_172
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getValue()="255"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(SizeofTypeOperator).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getValue()="255"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(SubExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(ComplementExpr).getOperand().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getLeftOperand().(Literal).getValue()="64"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getLeftOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_2.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(SubExpr).getRightOperand().(Literal).getValue()="7")
}

predicate func_3(Variable vmvif_171) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="bitrate_mask"
		and target_3.getQualifier().(VariableAccess).getTarget()=vmvif_171)
}

predicate func_4(Variable vi_172) {
	exists(PostfixIncrExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vi_172)
}

from Function func, Variable vmvif_171, Variable vi_172
where
not func_0(vmvif_171, vi_172)
and not func_1(vmvif_171, vi_172)
and not func_2(vmvif_171, vi_172)
and vmvif_171.getType().hasName("mt7915_vif *")
and func_3(vmvif_171)
and vi_172.getType().hasName("int")
and func_4(vi_172)
and vmvif_171.getParentScope+() = func
and vi_172.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
