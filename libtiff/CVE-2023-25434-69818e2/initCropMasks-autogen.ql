/**
 * @name libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-initCropMasks
 * @id cpp/libtiff/69818e2f2d246e6631ac2a2da692c3706b849c38/initCropMasks
 * @description libtiff-69818e2f2d246e6631ac2a2da692c3706b849c38-tools/tiffcrop.c-initCropMasks CVE-2023-25434
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_5754, Parameter vcps_5752, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffptr"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcps_5752
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_5754
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vi_5754, Parameter vcps_5752, ExprStmt target_0
where
func_0(vi_5754, vcps_5752, target_0)
and vi_5754.getType().hasName("int")
and vcps_5752.getType().hasName("crop_mask *")
and vi_5754.(LocalVariable).getFunction() = func
and vcps_5752.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
