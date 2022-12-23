/**
 * @name linux-051ae669e4505abbe05165bebf6be7922de11f41-wilc_wfi_cfg_parse_ch_attr
 * @id cpp/linux/051ae669e4505abbe05165bebf6be7922de11f41/wilc_wfi_cfg_parse_ch_attr
 * @description linux-051ae669e4505abbe05165bebf6be7922de11f41-wilc_wfi_cfg_parse_ch_attr 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_4(Variable ve_951, Variable vindex_954, Variable vch_list_idx_955, Variable vop_ch_idx_956) {
	exists(IfStmt target_4 |
		target_4.getCondition() instanceof EqualityOperation
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vch_list_idx_955
		and target_4.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954
		and target_4.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand() instanceof EqualityOperation
		and target_4.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("u16")
		and target_4.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_4.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getLeftOperand().(SizeofTypeOperator).getValue()="8"
		and target_4.getElse().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(SubExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951
		and target_4.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vop_ch_idx_956
		and target_4.getElse().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954)
}

predicate func_6(Variable ve_951, Variable vindex_954) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vindex_954
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(SizeofExprOperator).getValue()="3"
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951
		and target_6.getExpr().(AssignAddExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getType().hasName("u16"))
}

predicate func_9(Variable ve_951, Variable vindex_954, Variable vch_list_idx_955) {
	exists(EqualityOperation target_9 |
		target_9.getAnOperand().(PointerFieldAccess).getTarget().getName()="attr_type"
		and target_9.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_951
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vch_list_idx_955
		and target_9.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954)
}

predicate func_10(Variable ve_951, Variable vindex_954, Variable vop_ch_idx_956) {
	exists(EqualityOperation target_10 |
		target_10.getAnOperand().(PointerFieldAccess).getTarget().getName()="attr_type"
		and target_10.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_951
		and target_10.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vop_ch_idx_956
		and target_10.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954)
}

predicate func_11(Variable ve_951) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="attr_len"
		and target_11.getQualifier().(VariableAccess).getTarget()=ve_951)
}

predicate func_12(Variable ve_951) {
	exists(SizeofExprOperator target_12 |
		target_12.getValue()="3"
		and target_12.getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951)
}

predicate func_13(Parameter vlen_949, Variable ve_951, Variable vindex_954) {
	exists(RelationalOperation target_13 |
		 (target_13 instanceof GEExpr or target_13 instanceof LEExpr)
		and target_13.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vindex_954
		and target_13.getLesserOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getValue()="3"
		and target_13.getLesserOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951
		and target_13.getGreaterOperand().(VariableAccess).getTarget()=vlen_949)
}

predicate func_14(Variable ve_951) {
	exists(PointerFieldAccess target_14 |
		target_14.getTarget().getName()="attr_type"
		and target_14.getQualifier().(VariableAccess).getTarget()=ve_951)
}

predicate func_16(Parameter vbuf_949, Variable vindex_954) {
	exists(ArrayExpr target_16 |
		target_16.getArrayBase().(VariableAccess).getTarget()=vbuf_949
		and target_16.getArrayOffset().(VariableAccess).getTarget()=vindex_954)
}

from Function func, Parameter vbuf_949, Parameter vlen_949, Variable ve_951, Variable vindex_954, Variable vch_list_idx_955, Variable vop_ch_idx_956
where
not func_4(ve_951, vindex_954, vch_list_idx_955, vop_ch_idx_956)
and not func_6(ve_951, vindex_954)
and func_9(ve_951, vindex_954, vch_list_idx_955)
and func_10(ve_951, vindex_954, vop_ch_idx_956)
and func_11(ve_951)
and func_12(ve_951)
and vlen_949.getType().hasName("u32")
and func_13(vlen_949, ve_951, vindex_954)
and ve_951.getType().hasName("wilc_attr_entry *")
and func_14(ve_951)
and vindex_954.getType().hasName("u32")
and func_16(vbuf_949, vindex_954)
and vch_list_idx_955.getType().hasName("u8")
and vop_ch_idx_956.getType().hasName("u8")
and vbuf_949.getParentScope+() = func
and vlen_949.getParentScope+() = func
and ve_951.getParentScope+() = func
and vindex_954.getParentScope+() = func
and vch_list_idx_955.getParentScope+() = func
and vop_ch_idx_956.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
