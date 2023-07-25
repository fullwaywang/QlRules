/**
 * @name libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-extractCompositeRegions
 * @id cpp/libtiff/afaabc3e50d4e5d80a94143f7e3c997e7e410f68/extractCompositeRegions
 * @description libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-tools/tiffcrop.c-extractCompositeRegions CVE-2023-0795
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_7290, Parameter vcrop_7285, PointerFieldAccess target_0) {
		target_0.getTarget().getName()="regionlist"
		and target_0.getQualifier().(VariableAccess).getTarget()=vcrop_7285
		and target_0.getParent().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_7290
}

predicate func_1(Parameter vcrop_buff_7287, Variable vi_7290, Parameter vcrop_7285, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffptr"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_7285
		and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_7290
		and target_1.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcrop_buff_7287
}

from Function func, Parameter vcrop_buff_7287, Variable vi_7290, Parameter vcrop_7285, PointerFieldAccess target_0, ExprStmt target_1
where
func_0(vi_7290, vcrop_7285, target_0)
and func_1(vcrop_buff_7287, vi_7290, vcrop_7285, target_1)
and vcrop_buff_7287.getType().hasName("unsigned char *")
and vi_7290.getType().hasName("uint32_t")
and vcrop_7285.getType().hasName("crop_mask *")
and vcrop_buff_7287.getFunction() = func
and vi_7290.(LocalVariable).getFunction() = func
and vcrop_7285.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
