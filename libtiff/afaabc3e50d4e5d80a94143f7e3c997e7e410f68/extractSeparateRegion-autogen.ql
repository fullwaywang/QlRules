/**
 * @name libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-extractSeparateRegion
 * @id cpp/libtiff/afaabc3e50d4e5d80a94143f7e3c997e7e410f68/extractSeparateRegion
 * @description libtiff-afaabc3e50d4e5d80a94143f7e3c997e7e410f68-tools/tiffcrop.c-extractSeparateRegion CVE-2023-0795
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcrop_7600, Parameter vcrop_buff_7602, Parameter vregion_7602, Function func, ExprStmt target_0) {
		target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="buffptr"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="regionlist"
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcrop_7600
		and target_0.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vregion_7602
		and target_0.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcrop_buff_7602
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
}

from Function func, Parameter vcrop_7600, Parameter vcrop_buff_7602, Parameter vregion_7602, ExprStmt target_0
where
func_0(vcrop_7600, vcrop_buff_7602, vregion_7602, func, target_0)
and vcrop_7600.getType().hasName("crop_mask *")
and vcrop_buff_7602.getType().hasName("unsigned char *")
and vregion_7602.getType().hasName("int")
and vcrop_7600.getFunction() = func
and vcrop_buff_7602.getFunction() = func
and vregion_7602.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
