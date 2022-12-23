/**
 * @name linux-f9b62f9843c7b0afdaecabbcebf1dbba18599408-wilc_wfi_cfg_parse_ch_attr
 * @id cpp/linux/f9b62f9843c7b0afdaecabbcebf1dbba18599408/wilc-wfi-cfg-parse-ch-attr
 * @description linux-f9b62f9843c7b0afdaecabbcebf1dbba18599408-wilc_wfi_cfg_parse_ch_attr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable ve_951, Variable vindex_954, Variable vch_list_idx_955, Variable vattr_size_962) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vattr_size_962
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="3"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofTypeOperator).getValue()="6"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(SizeofExprOperator).getValue()="3"
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vch_list_idx_955
		and target_0.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954)
}

predicate func_1(Variable ve_951, Variable vindex_954, Variable vch_list_idx_955) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="attr_type"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=ve_951
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vch_list_idx_955
		and target_1.getParent().(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vindex_954)
}

predicate func_2(Variable ve_951) {
	exists(PointerDereferenceExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=ve_951)
}

predicate func_3(Parameter vlen_949, Variable ve_951, Variable vindex_954, Variable vattr_size_962) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vindex_954
		and target_3.getAnOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getValue()="3"
		and target_3.getAnOperand().(AddExpr).getAnOperand().(SizeofExprOperator).getExprOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=ve_951
		and target_3.getAnOperand().(VariableAccess).getTarget()=vattr_size_962
		and target_3.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vlen_949
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen().(ReturnStmt).toString() = "return ...")
}

from Function func, Parameter vlen_949, Variable ve_951, Variable vindex_954, Variable vch_list_idx_955, Variable vattr_size_962
where
not func_0(ve_951, vindex_954, vch_list_idx_955, vattr_size_962)
and func_1(ve_951, vindex_954, vch_list_idx_955)
and ve_951.getType().hasName("wilc_attr_entry *")
and func_2(ve_951)
and vindex_954.getType().hasName("u32")
and vch_list_idx_955.getType().hasName("u8")
and vattr_size_962.getType().hasName("u16")
and func_3(vlen_949, ve_951, vindex_954, vattr_size_962)
and vlen_949.getParentScope+() = func
and ve_951.getParentScope+() = func
and vindex_954.getParentScope+() = func
and vch_list_idx_955.getParentScope+() = func
and vattr_size_962.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
