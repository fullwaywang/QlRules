/**
 * @name libpng-812768d7a9c973452222d454634496b25ed415eb-png_free_data
 * @id cpp/libpng/812768d7a9c973452222d454634496b25ed415eb/png-free-data
 * @description libpng-812768d7a9c973452222d454634496b25ed415eb-png_free_data CVE-2016-10087
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vinfo_ptr_451, Parameter vnum_452) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="max_text"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_ptr_451
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnum_452
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="-1")
}

predicate func_1(Parameter vinfo_ptr_451) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="num_text"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_ptr_451
		and target_1.getRValue().(Literal).getValue()="0")
}

from Function func, Parameter vinfo_ptr_451, Parameter vnum_452
where
not func_0(vinfo_ptr_451, vnum_452)
and vinfo_ptr_451.getType().hasName("png_inforp")
and func_1(vinfo_ptr_451)
and vnum_452.getType().hasName("int")
and vinfo_ptr_451.getParentScope+() = func
and vnum_452.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
