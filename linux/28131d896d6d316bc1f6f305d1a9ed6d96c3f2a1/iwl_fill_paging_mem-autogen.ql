/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fill_paging_mem
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/iwl-fill-paging-mem
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-iwl_fill_paging_mem CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_4(Parameter vfwrt_108, Parameter vimage_109, Variable vsec_idx_111, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="fw_offs"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="fw_paging_db"
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfwrt_108
		and target_4.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="offset"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sec"
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_109
		and target_4.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsec_idx_111
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_4))
}

predicate func_5(Parameter vimage_109, Variable vsec_idx_111, Variable voffset_112, Variable vblock_172) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="fw_offs"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vblock_172
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getTarget().getName()="offset"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sec"
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_109
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsec_idx_111
		and target_5.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_112)
}

predicate func_10(Parameter vfwrt_108) {
	exists(PointerFieldAccess target_10 |
		target_10.getTarget().getName()="fw_paging_db"
		and target_10.getQualifier().(VariableAccess).getTarget()=vfwrt_108)
}

predicate func_11(Parameter vimage_109) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="sec"
		and target_11.getQualifier().(VariableAccess).getTarget()=vimage_109)
}

predicate func_13(Parameter vimage_109, Variable vsec_idx_111) {
	exists(ArrayExpr target_13 |
		target_13.getArrayBase().(PointerFieldAccess).getTarget().getName()="sec"
		and target_13.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_109
		and target_13.getArrayOffset().(VariableAccess).getTarget()=vsec_idx_111)
}

predicate func_15(Parameter vimage_109, Variable vsec_idx_111, Variable voffset_112, Variable vblock_172, Variable vlen_174) {
	exists(PointerArithmeticOperation target_15 |
		target_15.getAnOperand().(ValueFieldAccess).getTarget().getName()="data"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sec"
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vimage_109
		and target_15.getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vsec_idx_111
		and target_15.getAnOperand().(VariableAccess).getTarget()=voffset_112
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__memcpy")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("lowmem_page_address")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="fw_paging_block"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vblock_172
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vlen_174)
}

predicate func_16(Variable vblock_172) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="fw_paging_block"
		and target_16.getQualifier().(VariableAccess).getTarget()=vblock_172)
}

from Function func, Parameter vfwrt_108, Parameter vimage_109, Variable vsec_idx_111, Variable voffset_112, Variable vblock_172, Variable vlen_174
where
not func_4(vfwrt_108, vimage_109, vsec_idx_111, func)
and not func_5(vimage_109, vsec_idx_111, voffset_112, vblock_172)
and vfwrt_108.getType().hasName("iwl_fw_runtime *")
and func_10(vfwrt_108)
and vimage_109.getType().hasName("const fw_img *")
and func_11(vimage_109)
and vsec_idx_111.getType().hasName("int")
and func_13(vimage_109, vsec_idx_111)
and voffset_112.getType().hasName("u32")
and func_15(vimage_109, vsec_idx_111, voffset_112, vblock_172, vlen_174)
and vblock_172.getType().hasName("iwl_fw_paging *")
and func_16(vblock_172)
and vlen_174.getType().hasName("int")
and vfwrt_108.getParentScope+() = func
and vimage_109.getParentScope+() = func
and vsec_idx_111.getParentScope+() = func
and voffset_112.getParentScope+() = func
and vblock_172.getParentScope+() = func
and vlen_174.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
