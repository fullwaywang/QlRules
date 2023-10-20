/**
 * @name libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-extractCompositeRegions
 * @id cpp/libtiff/69818e2f2d246e6631ac2a2da692c3706b849c38/extractCompositeRegions
 * @description libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-tools/tiffcrop.c-extractCompositeRegions CVE-2023-25434
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
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
