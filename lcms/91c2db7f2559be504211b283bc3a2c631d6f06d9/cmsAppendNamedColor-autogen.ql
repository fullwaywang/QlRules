/**
 * @name lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-cmsAppendNamedColor
 * @id cpp/lcms/91c2db7f2559be504211b283bc3a2c631d6f06d9/cmsAppendNamedColor
 * @description lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-src/cmsnamed.c-cmsAppendNamedColor CVE-2013-4160
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

/*predicate func_1(Parameter vNamedColorList_560, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="List"
		and target_1.getQualifier().(VariableAccess).getTarget()=vNamedColorList_560
		and target_1.getParent().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getTarget().getName()="nColors"
		and target_1.getParent().(ArrayExpr).getArrayOffset().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vNamedColorList_560
}

*/
/*predicate func_2(Parameter vNamedColorList_560, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="nColors"
		and target_2.getQualifier().(VariableAccess).getTarget()=vNamedColorList_560
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="List"
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vNamedColorList_560
}

*/
predicate func_3(Function func, SizeofExprOperator target_3) {
		target_3.getValue()="256"
		and target_3.getEnclosingFunction() = func
}

from Function func, Parameter vNamedColorList_560, SizeofExprOperator target_3
where
func_3(func, target_3)
and vNamedColorList_560.getType().hasName("cmsNAMEDCOLORLIST *")
and vNamedColorList_560.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
